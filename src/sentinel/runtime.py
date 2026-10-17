"""Wires the components together. Tools and their target systems are owned here; agents only
ever receive a `GatewayClient`."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sentinel.ai import AISupervisor, Provider
from sentinel.approvals import ApprovalService
from sentinel.audit import AuditStore
from sentinel.contracts import CallOutcome, Mode
from sentinel.dataflow import DataFlowTracker
from sentinel.fixtures import build_systems
from sentinel.gateway import Gateway, GatewayClient, Listener
from sentinel.identity import IdentityRegistry, PrincipalKind
from sentinel.monitor import Monitor
from sentinel.policy import PolicyEngine
from sentinel.safemode import RecoveryError, SafeModeController, Transition
from sentinel.tools.adapters import build_adapters
from sentinel.tools.systems import Systems
from sentinel.verification import OutcomeVerifier
from sentinel.watchdog import Watchdog


def _default_policy() -> Path:
    """Repo checkout → policies/default.yaml; installed wheel → the copy shipped in the package."""
    repo = Path(__file__).resolve().parents[2] / "policies" / "default.yaml"
    return repo if repo.exists() else Path(__file__).resolve().parent / "data" / "default.yaml"


DEFAULT_POLICY = _default_policy()


@dataclass
class Runtime:
    systems: Systems
    store: AuditStore
    policy: PolicyEngine
    identities: IdentityRegistry
    gateway: Gateway
    controller: SafeModeController
    watchdog: Watchdog
    monitor: Monitor
    ai: AISupervisor | None = None

    @classmethod
    def build(
        cls, db_path: Path | str, policy_path: Path | str = DEFAULT_POLICY,
        listeners: list[Listener] | None = None, tool_timeout_seconds: float = 5.0,
        required_healthy_rounds: int = 2,
        ai_provider: Provider | None = None,
    ) -> Runtime:
        systems = build_systems()
        store = AuditStore(db_path)
        policy = PolicyEngine(Path(policy_path))
        identities = IdentityRegistry()

        holder: dict[str, SafeModeController] = {}
        gateway = Gateway(
            identities=identities, policy=policy, store=store, adapters=build_adapters(systems),
            dataflow=DataFlowTracker(), approvals=ApprovalService(),
            verifier=OutcomeVerifier(systems),
            mode=lambda: holder["c"].mode if "c" in holder else Mode.RESTRICTED,
            tool_timeout_seconds=tool_timeout_seconds,
        )
        controller = SafeModeController(gateway.emit, lambda: policy.bundle.approvers,
                                        required_healthy_rounds=required_healthy_rounds)
        holder["c"] = controller
        for listener in listeners or []:
            gateway.listeners.append(listener)
        monitor = Monitor(gateway.emit)
        gateway.listeners.append(monitor)

        wd_cred = identities.register("service.watchdog", PrincipalKind.SERVICE, ("watchdog",))
        # A privileged synthetic identity: in NORMAL mode this request would be allowed, so a
        # refusal while RESTRICTED is real evidence that protected tools are contained.
        probe_cred = identities.register("service.containment-probe", PrincipalKind.SERVICE,
                                         ("support_agent",))

        def containment_probe() -> tuple[bool, dict]:
            writes_before = len(systems.crm.access_log())
            resp = gateway.call(probe_cred, {
                "tool_name": "crm.update_record", "run_id": "containment-probe",
                "arguments": {"record_id": "containment-probe", "field": "notes", "value": "x"},
            })
            touched = len(systems.crm.access_log()) != writes_before
            return (resp.outcome is CallOutcome.DENIED and not touched,
                    {"outcome": resp.outcome.value, "reasons": list(resp.reason_codes),
                     "target_touched": touched})

        controller.containment_probe = containment_probe
        watchdog = Watchdog(gateway=gateway, store=store, systems=systems,
                            controller=controller, credential=wd_cred)
        ai = None
        if ai_provider is not None:
            # Read-only observer: gets events, emits findings, holds no gateway credential.
            ai = AISupervisor(ai_provider, store, gateway.emit)
            gateway.listeners.append(ai)
        return cls(systems, store, policy, identities, gateway, controller, watchdog, monitor, ai)

    # ---- convenience ---------------------------------------------------------------------
    def agent(self, agent_id: str, roles: tuple[str, ...], run_id: str) -> GatewayClient:
        cred = self.identities.register(agent_id, PrincipalKind.AGENT, roles)
        return GatewayClient(self.gateway, cred, run_id)

    def human(self, human_id: str) -> str:
        return self.identities.register(human_id, PrincipalKind.HUMAN, ("human",))

    def recover(self, human_credential: str) -> Transition:
        """Lift safe mode. The approver is authenticated; the controller enforces health gates."""
        principal = self.identities.authenticate(human_credential)
        if principal.kind is not PrincipalKind.HUMAN:
            raise RecoveryError("APPROVER_NOT_HUMAN", "only a human approver can lift safe mode")
        return self.controller.recover(principal.principal_id)

    def close(self) -> None:
        if self.ai:
            self.ai.stop()
        self.watchdog.stop()
        self.gateway.close()
        self.store.close()
