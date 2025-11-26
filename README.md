# Show Security - Demonstração de Segurança em Django

Este projeto é uma aplicação Django desenvolvida para demonstrar funcionalidades de segurança, incluindo um modelo de usuário customizado e a implementação de autenticação de dois fatores (2FA) com senhas de uso único baseadas em tempo (TOTP).

## ✨ Funcionalidades

- **Modelo de Usuário Customizado**: Utiliza um `CustomUser` que herda do `AbstractUser` do Django, permitindo fácil extensibilidade.
- **Autenticação de Dois Fatores (2FA)**: Implementação de 2FA usando a biblioteca `pyotp`, adicionando uma camada extra de segurança ao login.
- **Interface de Administração Django**: Configuração padrão do admin para gerenciamento de usuários e outros modelos.
- **Estrutura Organizada**: O projeto segue as melhores práticas de organização de arquivos e diretórios do Django.

---

## 🚀 Como Rodar o Projeto Localmente

Siga os passos abaixo para configurar e executar o projeto em seu ambiente de desenvolvimento.

### Pré-requisitos

- Python 3.11+
- Git
- `pip` (gerenciador de pacotes do Python)

### 1. Clonar o Repositório

Abra seu terminal e clone o projeto para sua máquina local.

```bash
git clone https://github.com/pedro-rodiguero/show-security.git
cd show-security
```

### 2. Criar e Ativar um Ambiente Virtual

É uma boa prática usar um ambiente virtual (`venv`) para isolar as dependências do projeto.

```bash
# Criar o ambiente virtual
python -m venv venv

# Ativar o ambiente virtual
# No Windows:
venv\Scripts\activate

# No macOS/Linux:
source venv/bin/activate
```

Seu terminal deve agora indicar que você está no ambiente `(venv)`.

### 3. Instalar as Dependências

Instale todas as bibliotecas Python necessárias listadas no arquivo `requirements.txt`.

```bash
pip install -r requirements.txt
```

### 4. Aplicar as Migrações do Banco de Dados

Este comando irá criar o banco de dados SQLite e aplicar o schema necessário para os modelos da aplicação.

```bash
python show_security/manage.py migrate
```

### 5. Criar um Superusuário

Crie uma conta de administrador para acessar a interface de administração do Django.

```bash
python show_security/manage.py createsuperuser
```

Siga as instruções no terminal para definir um nome de usuário, e-mail e senha.

### 6. Executar o Servidor de Desenvolvimento

Inicie o servidor local do Django.

```bash
python show_security/manage.py runserver
```

O servidor estará rodando em `http://127.0.0.1:8000/`.

### 7. Acessar a Aplicação

- **Página de Admin**: Acesse `http://127.0.0.1:8000/admin/` e faça login com as credenciais do superusuário que você criou.

---

## ⚙️ Estrutura do Projeto

```
show-security/
├── .github/workflows/      # Contém os workflows do GitHub Actions (ex: deploy).
├── show_security/          # Diretório raiz do projeto Django.
│   ├── manage.py           # Utilitário de linha de comando do Django.
│   ├── show_security/      # Pacote Python do projeto (configurações, URLs).
│   ├── show_security_demo/ # App principal da aplicação.
│   └── templates/          # Templates HTML a nível de projeto.
├── static/                 # Arquivos estáticos (CSS, JS, imagens).
├── requirements.txt        # Lista de dependências Python.
└── README.md               # Este arquivo.
```

## 📦 Deploy

O workflow presente em `.github/workflows/deploy-pages.yml` está configurado para fazer o deploy dos **arquivos estáticos** do projeto para o **GitHub Pages**.

**Importante**: O GitHub Pages não executa código Python/Django. Este deploy serve apenas para hospedar os assets (CSS, JS, imagens). Para um deploy completo da aplicação, é necessário utilizar uma plataforma de hospedagem que suporte Python, como **PythonAnywhere**, **Heroku**, **Render** ou um servidor **VPS**.

---

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.