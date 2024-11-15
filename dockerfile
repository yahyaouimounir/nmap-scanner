# Utiliser Python 3.11 slim basé sur Debian Bookworm comme image de base
FROM python:3.11-slim-bookworm

# Mise à jour des paquets et installation de Nmap
RUN apt-get update && apt-get install -y nmap 
    
# Installation des dépendances Python nécessaires
RUN pip install matplotlib gradio python-nmap 

# Définir le répertoire de travail
WORKDIR /app

# Copier le script dans le conteneur
COPY port_scanner.py .

# Exposer le port 5000
EXPOSE 5000

# Lancer le script au démarrage du conteneur
CMD ["python", "port_scanner.py"]
