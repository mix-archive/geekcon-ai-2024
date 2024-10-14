from openai import AsyncOpenAI
import os

chat_client = AsyncOpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
)