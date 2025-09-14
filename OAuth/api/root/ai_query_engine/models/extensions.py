class OpenAILlmNoStreaming:
    """
    A wrapper around OpenAILlm that disables streaming responses.
    Specifically for use with the tool_calling_agent agent to enable the token counting callback
    """
    def __init__(self, llm):
        self.llm = llm

    def bind_tools(self, tools):
        return OpenAILlmNoStreaming(self.llm.bind_tools(tools))

    def __call__(self, prompt, config):
        return self.llm.invoke(prompt, config)
