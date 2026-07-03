import os

from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter

from langchain_huggingface import HuggingFaceEmbeddings

from langchain_community.vectorstores import Chroma

from utils.llm import llm


class RAGAgent:

    def __init__(self):

        self.persist_directory = "data/vector_db"

        self.embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2"
        )

        self.vector_db = None

        if os.path.exists(self.persist_directory):

            self.vector_db = Chroma(
                persist_directory=self.persist_directory,
                embedding_function=self.embeddings
            )

    # -----------------------------------------
    # Create Knowledge Base
    # -----------------------------------------

    def ingest_pdf(self, pdf_path):

        loader = PyPDFLoader(pdf_path)

        documents = loader.load()

        splitter = RecursiveCharacterTextSplitter(
            chunk_size=800,
            chunk_overlap=100
        )

        chunks = splitter.split_documents(documents)

        self.vector_db = Chroma.from_documents(
            documents=chunks,
            embedding=self.embeddings,
            persist_directory=self.persist_directory
        )

        print("Knowledge Base Created Successfully.")

    # -----------------------------------------
    # Ask Question
    # -----------------------------------------

    def ask(self, question):

        if self.vector_db is None:

            return "Please upload a cybersecurity PDF first."

        docs = self.vector_db.similarity_search(
            question,
            k=4
        )

        context = "\n\n".join(
            [doc.page_content for doc in docs]
        )

        prompt = f"""
You are SentinelAI.

Answer the user's question ONLY using the context below.

If the answer is unavailable, say:

"I couldn't find this information in the uploaded documents."

Context:

{context}

Question:

{question}
"""

        response = llm.invoke(prompt)

        return response.content


if __name__ == "__main__":

    rag = RAGAgent()

    # Run once
    # rag.ingest_pdf("sample_logs/owasp.pdf")

    answer = rag.ask("What is SQL Injection?")

    print(answer)