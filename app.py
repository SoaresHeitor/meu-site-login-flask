# Importa as ferramentas necessárias do Flask e do SQLite
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
import os

# --- CONFIGURAÇÃO INICIAL ---
app = Flask(__name__)
# Chave secreta necessária para o Flask gerenciar sessões (lembrar quem está logado)
app.secret_key = os.urandom(24) 

DATABASE = 'database.db'

# --- FUNÇÕES DO BANCO DE DADOS ---

def get_db():
    """Conecta ao banco de dados, criando-o se não existir."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Fecha a conexão com o banco de dados ao final da requisição."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Função para criar a tabela de usuários (substitui o phpMyAdmin)."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            '''
        )
        db.commit()


# --- ROTAS DA APLICAÇÃO (Onde a mágica acontece) ---

@app.route('/')
def home():
    """Página inicial, redireciona para o login."""
    return redirect(url_for('login'))

@app.route('/cadastrar', methods=['GET', 'POST'])
def cadastrar():
    if request.method == 'POST':
        # Obter dados do formulário
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Criptografar a senha
        password_hash = generate_password_hash(password)
        
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash)
            )
            db.commit()
            return "<h1>Usuário cadastrado com sucesso!</h1><a href='/login'>Fazer Login</a>"
        except sqlite3.IntegrityError:
            return "<h1>Erro: Este email já está cadastrado.</h1><a href='/cadastrar'>Tentar novamente</a>"

    # Se for GET, apenas mostra o formulário
    return render_template('cadastro.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone() # Pega o primeiro resultado

        # Verifica se o usuário existe E se a senha está correta
        if user and check_password_hash(user[3], password): # user[3] é a coluna password_hash
            session['user_id'] = user[0] # user[0] é a coluna id
            session['username'] = user[1] # user[1] é a coluna username
            return redirect(url_for('painel'))
        else:
            return "<h1>Email ou senha inválidos.</h1><a href='/login'>Tentar novamente</a>"

    return render_template('login.html')


@app.route('/painel')
def painel():
    # Verifica se o usuário está logado
    if 'user_id' in session:
        # Passa o nome de usuário para o template
        username = session['username']
        return f"<h1>Bem-vindo ao seu painel, {username}!</h1><p>Isto é Python!</p><a href='/logout'>Sair</a>"
    else:
        # Se não estiver logado, redireciona para a página de login
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('user_id', None) # Remove o usuário da sessão
    session.pop('username', None)
    return redirect(url_for('login'))


# --- RODA A APLICAÇÃO ---
if __name__ == '__main__':
    # Cria o banco de dados e a tabela na primeira vez que rodar
    init_db() 
    # Inicia o servidor de desenvolvimento
    app.run(debug=True)