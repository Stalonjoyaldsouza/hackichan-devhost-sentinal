"""Entry point: a tiny two-agent support workflow."""

from llm import ask


class Agent:
    def __init__(self, name: str):
        self.name = name


def triage(question: str) -> str:
    return ask([{"role": "system", "content": "Classify the request."},
                {"role": "user", "content": question}])


def handle(question: str) -> str:
    category = triage(question)
    billing_agent = Agent("billing")
    return ask([{"role": "system", "content": f"You are the {billing_agent.name} agent."},
                {"role": "user", "content": f"[{category}] {question}"}])


if __name__ == "__main__":
    print(handle("Please refund order 1234 and email me the receipt."))
