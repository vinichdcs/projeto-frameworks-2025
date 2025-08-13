from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = 'troque-esta-chave-para-producao'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://mp:hellen13@localhost:3306/bancomp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Usuario(db.Model):
    __tablename__ = 'usuario'
    id = db.Column('usu_id', db.Integer, primary_key=True)
    nome = db.Column('usu_nome', db.String(256))
    email = db.Column('usu_email', db.String(256))
    senha = db.Column('usu_senha', db.String(256))
    anuncios = db.relationship('Anuncio', backref='usuario', lazy=True)
    perguntas = db.relationship('Pergunta', backref='usuario', lazy=True)

class Anuncio(db.Model):
    __tablename__ = 'anuncio'
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100))
    descricao = db.Column(db.Text)
    preco = db.Column(db.Float)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.usu_id'), nullable=False)
    perguntas = db.relationship('Pergunta', backref='anuncio', lazy=True)

class Pergunta(db.Model):
    __tablename__ = 'pergunta'
    id = db.Column(db.Integer, primary_key=True)
    texto = db.Column(db.Text)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.usu_id'), nullable=False)
    id_anuncio = db.Column(db.Integer, db.ForeignKey('anuncio.id'), nullable=False)




@app.route('/usuario')
def listar_usuarios():
    usuarios = Usuario.query.all()
    return render_template('usuario.html', usuarios=usuarios)

@app.route('/usuario/novo', methods=['GET', 'POST'])
def novo_usuario():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']
        if not nome or not email or not senha:
            flash('Preencha todos os campos!')
            return redirect(url_for('novo_usuario'))
        novo = Usuario(nome=nome, email=email, senha=senha)
        db.session.add(novo)
        db.session.commit()
        flash('Usuário criado com sucesso!')
        return redirect(url_for('listar_usuarios'))
    return render_template('usuario_form.html', usuario=None)

@app.route('/usuario/editar/<int:id>', methods=['GET', 'POST'])
def editar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    if request.method == 'POST':
        usuario.nome = request.form['nome']
        usuario.email = request.form['email']
        senha = request.form['senha']
        if senha:
            usuario.senha = senha
        db.session.commit()
        flash('Usuário atualizado com sucesso!')
        return redirect(url_for('listar_usuarios'))
    return render_template('usuario_form.html', usuario=usuario)

@app.route('/usuario/deletar/<int:id>', methods=['GET', 'POST'])
def deletar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    if request.method == 'POST':
        db.session.delete(usuario)
        db.session.commit()
        flash('Usuário excluído com sucesso!')
        return redirect(url_for('listar_usuarios'))
    return render_template('usuario_delete.html', usuario=usuario)




@app.route('/anuncio')
def listar_anuncios():
    anuncios = Anuncio.query.all()
    usuarios = Usuario.query.all()
    return render_template('anuncio.html', anuncios=anuncios, usuarios=usuarios)

@app.route('/anuncio/novo', methods=['GET', 'POST'])
def novo_anuncio():
    usuarios = Usuario.query.all()
    if request.method == 'POST':
        titulo = request.form['titulo']
        descricao = request.form['descricao']
        preco = request.form['preco']
        id_usuario = request.form['id_usuario']
        if not titulo or not preco or not id_usuario:
            flash('Título, preço e usuário são obrigatórios!')
            return redirect(url_for('novo_anuncio'))
        novo = Anuncio(titulo=titulo, descricao=descricao, preco=float(preco), id_usuario=int(id_usuario))
        db.session.add(novo)
        db.session.commit()
        flash('Anúncio criado com sucesso!')
        return redirect(url_for('listar_anuncios'))
    return render_template('anuncio_form.html', anuncio=None, usuarios=usuarios)

@app.route('/anuncio/editar/<int:id>', methods=['GET', 'POST'])
def editar_anuncio(id):
    anuncio = Anuncio.query.get_or_404(id)
    usuarios = Usuario.query.all()
    if request.method == 'POST':
        anuncio.titulo = request.form['titulo']
        anuncio.descricao = request.form['descricao']
        anuncio.preco = float(request.form['preco'])
        anuncio.id_usuario = int(request.form['id_usuario'])
        db.session.commit()
        flash('Anúncio atualizado com sucesso!')
        return redirect(url_for('listar_anuncios'))
    return render_template('anuncio_form.html', anuncio=anuncio, usuarios=usuarios)

@app.route('/anuncio/deletar/<int:id>', methods=['GET', 'POST'])
def deletar_anuncio(id):
    anuncio = Anuncio.query.get_or_404(id)
    if request.method == 'POST':
        db.session.delete(anuncio)
        db.session.commit()
        flash('Anúncio excluído com sucesso!')
        return redirect(url_for('listar_anuncios'))
    return render_template('anuncio_delete.html', anuncio=anuncio)




@app.route('/pergunta')
def listar_perguntas():
    perguntas = Pergunta.query.all()
    usuarios = Usuario.query.all()
    anuncios = Anuncio.query.all()
    return render_template('pergunta.html', perguntas=perguntas, usuarios=usuarios, anuncios=anuncios)

@app.route('/pergunta/nova', methods=['GET', 'POST'])
def nova_pergunta():
    usuarios = Usuario.query.all()
    anuncios = Anuncio.query.all()
    if request.method == 'POST':
        texto = request.form['texto']
        id_usuario = request.form['id_usuario']
        id_anuncio = request.form['id_anuncio']
        if not texto or not id_usuario or not id_anuncio:
            flash('Preencha todos os campos!')
            return redirect(url_for('nova_pergunta'))
        nova = Pergunta(texto=texto, id_usuario=int(id_usuario), id_anuncio=int(id_anuncio))
        db.session.add(nova)
        db.session.commit()
        flash('Pergunta criada com sucesso!')
        return redirect(url_for('listar_perguntas'))
    return render_template('pergunta_form.html', pergunta=None, usuarios=usuarios, anuncios=anuncios)

@app.route('/pergunta/editar/<int:id>', methods=['GET', 'POST'])
def editar_pergunta(id):
    pergunta = Pergunta.query.get_or_404(id)
    usuarios = Usuario.query.all()
    anuncios = Anuncio.query.all()
    if request.method == 'POST':
        pergunta.texto = request.form['texto']
        pergunta.id_usuario = int(request.form['id_usuario'])
        pergunta.id_anuncio = int(request.form['id_anuncio'])
        db.session.commit()
        flash('Pergunta atualizada com sucesso!')
        return redirect(url_for('listar_perguntas'))
    return render_template('pergunta_form.html', pergunta=pergunta, usuarios=usuarios, anuncios=anuncios)

@app.route('/pergunta/deletar/<int:id>', methods=['GET', 'POST'])
def deletar_pergunta(id):
    pergunta = Pergunta.query.get_or_404(id)
    if request.method == 'POST':
        db.session.delete(pergunta)
        db.session.commit()
        flash('Pergunta excluída com sucesso!')
        return redirect(url_for('listar_perguntas'))
    return render_template('pergunta_delete.html', pergunta=pergunta)




@app.route('/')
def index():
    anuncios = Anuncio.query.all()
    return render_template('index.html', anuncios=anuncios)


if __name__ == '__main__':
    app.run(debug=True)