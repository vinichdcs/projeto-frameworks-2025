from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.secret_key = 'troque-esta-chave-para-producao' 

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://mp:hellen13@localhost:3306/bancomp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)



class Usuario(db.Model):
    __tablename__ = 'usuario'
    id = db.Column('usu_id', db.Integer, primary_key=True)
    nome = db.Column('usu_nome', db.String(256))
    email = db.Column('usu_email', db.String(256), unique=True, nullable=False)
    senha = db.Column('usu_senha', db.String(256))
    anuncios = db.relationship('Anuncio', backref='usuario', lazy=True, cascade="all, delete-orphan")
    perguntas = db.relationship('Pergunta', backref='usuario', lazy=True, cascade="all, delete-orphan")


class Anuncio(db.Model):
    __tablename__ = 'anuncio'
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100))
    descricao = db.Column(db.Text)
    preco = db.Column(db.Float)
    imagem_url = db.Column(db.String(256))
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.usu_id'), nullable=False)
    perguntas = db.relationship('Pergunta', backref='anuncio', lazy=True, cascade="all, delete-orphan")


class Pergunta(db.Model):
    __tablename__ = 'pergunta'
    id = db.Column(db.Integer, primary_key=True)
    texto = db.Column(db.Text)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.usu_id'), nullable=False)
    id_anuncio = db.Column(db.Integer, db.ForeignKey('anuncio.id'), nullable=False)



def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        usuario = Usuario.query.filter_by(email=email).first()
        if usuario and check_password_hash(usuario.senha, senha):
            session['usuario_id'] = usuario.id
            session['usuario_nome'] = usuario.nome
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Email ou senha inválidos.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('usuario_id', None)
    session.pop('usuario_nome', None)
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('index'))


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']

        if not nome or not email or not senha:
            flash('Preencha todos os campos!', 'danger')
            return redirect(url_for('cadastro'))

        usuario_existente = Usuario.query.filter_by(email=email).first()
        if usuario_existente:
            flash('Este e-mail já está cadastrado.', 'danger')
            return redirect(url_for('cadastro'))

        novo_usuario = Usuario(nome=nome, email=email, senha=generate_password_hash(senha))
        db.session.add(novo_usuario)
        db.session.commit()

        flash('Cadastro realizado com sucesso! Agora você pode fazer o login.', 'success')
        return redirect(url_for('login'))

    return render_template('cadastro.html')


@app.route('/usuario')
@login_required
def listar_usuarios():
    usuarios = Usuario.query.all()
    return render_template('usuario.html', usuarios=usuarios)


@app.route('/usuario/novo', methods=['GET', 'POST'])
@login_required
def novo_usuario():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']
        if not nome or not email or not senha:
            flash('Preencha todos os campos!', 'danger')
            return redirect(url_for('novo_usuario'))
        novo = Usuario(nome=nome, email=email, senha=generate_password_hash(senha))
        db.session.add(novo)
        db.session.commit()
        flash('Usuário criado com sucesso!', 'success')
        return redirect(url_for('listar_usuarios'))
    return render_template('usuario_form.html', usuario=None)


@app.route('/usuario/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    if request.method == 'POST':
        usuario.nome = request.form['nome']
        usuario.email = request.form['email']
        senha = request.form['senha']
        if senha:
            usuario.senha = generate_password_hash(senha)
        db.session.commit()
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('listar_usuarios'))
    return render_template('usuario_form.html', usuario=usuario)


@app.route('/usuario/deletar/<int:id>', methods=['GET', 'POST'])
@login_required
def deletar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    if request.method == 'POST':
        db.session.delete(usuario)
        db.session.commit()
        flash('Usuário excluído com sucesso!', 'info')
        return redirect(url_for('listar_usuarios'))
    return render_template('usuario_delete.html', usuario=usuario)



@app.route('/anuncio')
def listar_anuncios():
    anuncios = Anuncio.query.all()
    return render_template('anuncio.html', anuncios=anuncios)


@app.route('/anuncio/novo', methods=['GET', 'POST'])
@login_required
def novo_anuncio():
    if request.method == 'POST':
        titulo = request.form['titulo']
        descricao = request.form['descricao']
        preco_input = request.form['preco']

        try:
            preco = float(preco_input)
        except ValueError:
            flash('Preço inválido!', 'danger')
            return redirect(url_for('novo_anuncio'))

        id_usuario = session['usuario_id']

        
        imagem_url = None
        if 'imagem' in request.files:
            file = request.files['imagem']
            if file.filename != '':
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                imagem_url = f"/{app.config['UPLOAD_FOLDER']}/{filename}"


        if not titulo or not preco_input:
            flash('Título e preço são obrigatórios!', 'danger')
            return redirect(url_for('novo_anuncio'))

        novo = Anuncio(
            titulo=titulo, 
            descricao=descricao, 
            preco=preco, 
            imagem_url=imagem_url, 
            id_usuario=id_usuario
        )
        db.session.add(novo)
        db.session.commit()
        flash('Anúncio criado com sucesso!', 'success')
        return redirect(url_for('listar_anuncios'))
    
    return render_template('anuncio_form.html', anuncio=None)


@app.route('/anuncio/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_anuncio(id):
    anuncio = Anuncio.query.get_or_404(id)
    
    if anuncio.id_usuario != session['usuario_id']:
        flash('Você não tem permissão para editar este anúncio.', 'danger')
        return redirect(url_for('listar_anuncios'))
        
    if request.method == 'POST':
        anuncio.titulo = request.form['titulo']
        anuncio.descricao = request.form['descricao']

        try:
            anuncio.preco = float(request.form['preco'])
        except ValueError:
            flash('Preço inválido!', 'danger')
            return redirect(url_for('editar_anuncio', id=id))

       
        imagem = request.files.get('imagem')
        if imagem and imagem.filename != '':
            filename = secure_filename(imagem.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            imagem.save(filepath)
            anuncio.imagem_url = f"/{app.config['UPLOAD_FOLDER']}/{filename}"

        db.session.commit()
        flash('Anúncio atualizado com sucesso!', 'success')
        return redirect(url_for('listar_anuncios'))
    
    return render_template('anuncio_form.html', anuncio=anuncio)


@app.route('/anuncio/deletar/<int:id>', methods=['GET', 'POST'])
@login_required
def deletar_anuncio(id):
    anuncio = Anuncio.query.get_or_404(id)
    
    if anuncio.id_usuario != session['usuario_id']:
        flash('Você não tem permissão para excluir este anúncio.', 'danger')
        return redirect(url_for('listar_anuncios'))
        
    if request.method == 'POST':
        db.session.delete(anuncio)
        db.session.commit()
        flash('Anúncio excluído com sucesso!', 'info')
        return redirect(url_for('listar_anuncios'))
    return render_template('anuncio_delete.html', anuncio=anuncio)


@app.route('/pergunta')
def listar_perguntas():
    perguntas = Pergunta.query.all()
    return render_template('pergunta.html', perguntas=perguntas)


@app.route('/pergunta/nova', methods=['GET', 'POST'])
@login_required
def nova_pergunta():
    anuncios = Anuncio.query.all()
    if request.method == 'POST':
        texto = request.form['texto']
        
        id_usuario = session['usuario_id']
        id_anuncio = request.form['id_anuncio']
        
        if not texto or not id_anuncio:
            flash('Preencha todos os campos!', 'danger')
            return redirect(url_for('nova_pergunta'))
            
        nova = Pergunta(texto=texto, id_usuario=id_usuario, id_anuncio=int(id_anuncio))
        db.session.add(nova)
        db.session.commit()
        flash('Pergunta criada com sucesso!', 'success')
        return redirect(url_for('listar_perguntas'))
        
    return render_template('pergunta_form.html', pergunta=None, anuncios=anuncios)


@app.route('/pergunta/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_pergunta(id):
    pergunta = Pergunta.query.get_or_404(id)
    
    if pergunta.id_usuario != session['usuario_id']:
        flash('Você não tem permissão para editar esta pergunta.', 'danger')
        return redirect(url_for('listar_perguntas'))
    
    anuncios = Anuncio.query.all()
    if request.method == 'POST':
        pergunta.texto = request.form['texto']
        pergunta.id_anuncio = int(request.form['id_anuncio'])
        db.session.commit()
        flash('Pergunta atualizada com sucesso!', 'success')
        return redirect(url_for('listar_perguntas'))
        
    return render_template('pergunta_form.html', pergunta=pergunta, anuncios=anuncios)


@app.route('/pergunta/deletar/<int:id>', methods=['GET', 'POST'])
@login_required
def deletar_pergunta(id):
    pergunta = Pergunta.query.get_or_404(id)
    
    if pergunta.id_usuario != session['usuario_id']:
        flash('Você não tem permissão para excluir esta pergunta.', 'danger')
        return redirect(url_for('listar_perguntas'))

    if request.method == 'POST':
        db.session.delete(pergunta)
        db.session.commit()
        flash('Pergunta excluída com sucesso!', 'info')
        return redirect(url_for('listar_perguntas'))
    return render_template('pergunta_delete.html', pergunta=pergunta)



@app.route('/')
def index():
    anuncios = Anuncio.query.all()
    return render_template('index.html', anuncios=anuncios)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)