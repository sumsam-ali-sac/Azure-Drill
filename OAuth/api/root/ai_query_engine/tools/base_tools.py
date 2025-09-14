from langchain.tools import tool
from langchain.pydantic_v1 import BaseModel, Field

# The tool arg_schema is optional, but recommended as it provides the agent with more information about tool args
class ToolSchema(BaseModel):
    input: type = Field(description="Description of the input")

@tool("tool_name", args_schema=ToolSchema)
def python_func(input: type) -> type:
    """
    Description of the tool
    :param input:
    :return:
    """
    pass