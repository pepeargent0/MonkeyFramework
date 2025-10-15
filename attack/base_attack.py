from abc import ABC, abstractmethod
import threading


class BaseAttack(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.running = False
        self.thread = None

    @abstractmethod
    def attack(self):
        """Método principal del ataque"""
        pass

    @abstractmethod
    def stop(self):
        """Detener ataque y limpiar"""
        pass

    def start(self):
        """Iniciar ataque en thread separado"""
        self.running = True
        self.thread = threading.Thread(target=self.attack)
        self.thread.start()

    def get_info(self):
        """Información del ataque"""
        return {
            "name": self.name,
            "description": self.description,
            "running": self.running
        }