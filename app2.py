"""
Sample application exercising several AI/ML components so that
Cisco AIBOM has concrete things to detect and inventory:
  - OpenAI SDK client + chat completion
  - Anthropic SDK client
  - LangChain LLM wiring
  - Hugging Face transformers pipeline + model load
  - sentence-transformers embeddings
"""

import os

from openai import OpenAI
from anthropic import Anthropic
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline
from sentence_transformers import SentenceTransformer


def openai_chat(prompt: str) -> str:
    """Call OpenAI's GPT model for a chat completion."""
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content


def anthropic_chat(prompt: str) -> str:
    """Call Anthropic's Claude model."""
    client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text


def langchain_summarize(text: str) -> str:
    """Summarize text using a LangChain chain over an OpenAI model."""
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    prompt = ChatPromptTemplate.from_messages(
        [("system", "Summarize the user's text in one sentence."), ("user", "{input}")]
    )
    chain = prompt | llm
    return chain.invoke({"input": text}).content


def hf_sentiment(text: str):
    """Run sentiment analysis with a Hugging Face transformers pipeline."""
    model_name = "distilbert-base-uncased-finetuned-sst-2-english"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    classifier = pipeline("sentiment-analysis", model=model, tokenizer=tokenizer)
    return classifier(text)


def embed(sentences):
    """Generate sentence embeddings with sentence-transformers."""
    model = SentenceTransformer("all-MiniLM-L6-v2")
    return model.encode(sentences)


if __name__ == "__main__":
    print(openai_chat("Hello!"))
    print(anthropic_chat("Hello!"))
    print(langchain_summarize("AIBOM inventories the AI components in a codebase."))
    print(hf_sentiment("I love this tool!"))
    print(embed(["first sentence", "second sentence"]))
