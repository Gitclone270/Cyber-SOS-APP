from kivy.app import App
from kivy.uix.button import Button

class CyberSOSApp(App):
    def build(self):
        return Button(
            text="🚨 SEND SOS",
            font_size=32
        )

CyberSOSApp().run()