import frida

class FridaAgent():
    def __init__(self) -> None:
        self.session = None
        self.script = None

    def _get_agent_script(self):
        with open('./dqx-blowfish-frida-agent/_agent.js', 'rt', encoding='utf-8') as f:
            return f.read()

    def attach_game(self):
        self.session = frida.attach("DQXGame.exe")
        self.script = self.session.create_script(self._get_agent_script())
        self.script.load()

    def detach_game(self):
        self.script.unload()

    def blowfish_decrypt(self, key: str, data: bytes) -> bytes:
        return self.script.exports.blowfish_decrypt(key, [b for b in data])

    def blowfish_encrypt(self, key: str, data: bytes) -> bytes:
        return self.script.exports.blowfish_encrypt(key, [b for b in data])