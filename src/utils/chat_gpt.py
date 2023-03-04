from revChatGPT.V3 import Chatbot
from application.settings import CHAT_GPT_KEY


class ChatGPTBot:
    def __init__(self) -> None:
        self.chatbot = Chatbot(api_key=CHAT_GPT_KEY)

    def ask(self, worlds):
        return self.chatbot.ask(worlds)


chat_bot = ChatGPTBot()
