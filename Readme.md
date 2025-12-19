# Secure Stream Cipher Chat

Une application de messagerie instantanée sécurisée en ligne de commande (CLI), développée en Rust. Ce projet implémente une architecture **Client/Serveur** protégée par un chiffrement de flux "maison" basé sur l'échange de clés Diffie-Hellman.

---

## Auteurs

Projet réalisé par :
* **Thibault GAUTHE**
* **Nathan GEORGES**
* **Maxime SCHOOSE**
* **Franck GIREL**

---

## 📺Démonstration Vidéo

Découvrez les fonctionnalités et le fonctionnement du code en vidéo :
**[vidéo explicative sur YouTube](https://youtu.be/I8ygbnjkI5w)**

---

## Fonctionnalités

* **Chiffrement de bout en bout :** Implémentation manuelle de Diffie-Hellman et d'un chiffrement XOR avec générateur LCG.
* **Interface Colorée :** Distinction visuelle claire entre le Client, le Serveur et les messages système.
* **Horodatage :** Chaque message est daté précisément.
* **Logs Persistants :** Sauvegarde automatique de l'historique dans un fichier `chat_history.txt` pour audit.

---

## Instructions de Compilation

Assurez-vous d'avoir **Rust** et **Cargo** installés.

1.  Clonez le dépôt :
    ```bash
    git clone [https://github.com/NathanG349/Rust_Project.git](https://github.com/NathanG349/Rust_Project.git)
    cd Rust_Project
    ```

2.  Compilez le projet (les dépendances seront téléchargées automatiquement) :
    ```bash
    cargo build --release
    ```

---

## Exemples d'Utilisation

Il faut deux terminaux pour utiliser l'application.

### 1. Lancer le Serveur
Dans le premier terminal, démarrez le serveur sur un port libre (ex: 8080) :
```bash
cargo run -- server 8080

Ensuite la meme chose avec un cargo run -- client IP:puis le port

et pour finir un /quit fermera l'échange et archivera la conversation dans un chat