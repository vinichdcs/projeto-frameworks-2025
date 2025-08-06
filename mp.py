from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)


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



@app.route('/')
def index():
    anuncios = Anuncio.query.all()
    return render_template('index.html', anuncios=anuncios)

@app.route('/usuario')
def usuario():
    usuarios = Usuario.query.all()
    return render_template('usuario.html', usuarios=usuarios)

@app.route('/usuario/novo', methods=['POST'])
def novo_usuario():
    nome = request.form['nome']
    email = request.form['email']
    senha = request.form['senha']
    novo = Usuario(nome=nome, email=email, senha=senha)
    db.session.add(novo)
    db.session.commit()
    return redirect(url_for('usuario'))

@app.route('/usuario/deletar/<int:id>')
def deletar_usuario(id):
    u = Usuario.query.get_or_404(id)
    db.session.delete(u)
    db.session.commit()
    return redirect(url_for('usuario'))

@app.route('/anuncio')
def anuncio():
    anuncios = Anuncio.query.all()
    usuarios = Usuario.query.all()
    return render_template('anuncio.html', anuncios=anuncios, usuarios=usuarios)

@app.route('/anuncio/novo', methods=['POST'])
def novo_anuncio():
    titulo = request.form['titulo']
    descricao = request.form['descricao']
    preco = request.form['preco']
    id_usuario = request.form['id_usuario']
    novo = Anuncio(titulo=titulo, descricao=descricao, preco=preco, id_usuario=id_usuario)
    db.session.add(novo)
    db.session.commit()
    return redirect(url_for('anuncio'))

@app.route('/anuncio/deletar/<int:id>')
def deletar_anuncio(id):
    a = Anuncio.query.get_or_404(id)
    db.session.delete(a)
    db.session.commit()
    return redirect(url_for('anuncio'))

@app.route('/pergunta')
def pergunta():
    perguntas = Pergunta.query.all()
    usuarios = Usuario.query.all()
    anuncios = Anuncio.query.all()
    return render_template('pergunta.html', perguntas=perguntas, usuarios=usuarios, anuncios=anuncios)

@app.route('/pergunta/nova', methods=['POST'])
def nova_pergunta():
    texto = request.form['texto']
    id_usuario = request.form['id_usuario']
    id_anuncio = request.form['id_anuncio']
    nova = Pergunta(texto=texto, id_usuario=id_usuario, id_anuncio=id_anuncio)
    db.session.add(nova)
    db.session.commit()
    return redirect(url_for('pergunta'))

@app.route('/pergunta/deletar/<int:id>')
def deletar_pergunta(id):
    p = Pergunta.query.get_or_404(id)
    db.session.delete(p)
    db.session.commit()
    return redirect(url_for('pergunta'))



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
