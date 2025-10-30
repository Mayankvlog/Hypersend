import flet as ft
from frontend.app import HyperSendApp

def main(page: ft.Page):
    app = HyperSendApp(page)

if __name__ == "__main__":
    ft.app(main)