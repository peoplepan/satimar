#!/usr/bin/env python3
"""API do Sistema de Controle de Funcionários (Satimar).

Guarda o estado do sistema (funcionarios, treinamentos, asos, vacinas) num
banco SQLite, com login por usuário/senha, controle de versão e histórico.
Usa só a biblioteca padrão do Python 3.10+.

Uso:
  python3 server.py                       inicia a API (127.0.0.1:8081)
  python3 server.py criar-usuario NOME    cria usuário ou troca a senha
  python3 server.py remover-usuario NOME  remove usuário e suas sessões
  python3 server.py listar-usuarios       lista os usuários
  python3 server.py backup PASTA          copia o banco para PASTA (mantém 30)
"""
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.environ.get('SATIMAR_DB', '/var/lib/satimar/satimar.db')
HOST = os.environ.get('SATIMAR_HOST', '127.0.0.1')
PORT = int(os.environ.get('SATIMAR_PORT', '8081'))
COOKIE_SECURE = os.environ.get('SATIMAR_COOKIE_SECURE', '1') == '1'
COOKIE = 'satimar_sid'
SESSAO_DIAS = 7
MAX_BODY = 5 * 1024 * 1024
HISTORICO_MAX = 300
LOGIN_MAX_FALHAS = 10
LOGIN_JANELA = 15 * 60

# ================= BANCO =================
def conectar():
    con = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA busy_timeout=10000')
    con.execute('PRAGMA foreign_keys=ON')
    return con


def criar_tabelas():
    d = os.path.dirname(DB_PATH)
    if d:
        os.makedirs(d, exist_ok=True)
    con = conectar()
    con.executescript('''
        CREATE TABLE IF NOT EXISTS estado (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            dados TEXT NOT NULL,
            versao INTEGER NOT NULL,
            atualizado_em TEXT NOT NULL,
            atualizado_por TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS historico (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            versao INTEGER NOT NULL,
            dados TEXT NOT NULL,
            salvo_em TEXT NOT NULL,
            salvo_por TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS usuarios (
            usuario TEXT PRIMARY KEY,
            senha_hash TEXT NOT NULL,
            criado_em TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessoes (
            token_hash TEXT PRIMARY KEY,
            usuario TEXT NOT NULL REFERENCES usuarios(usuario) ON DELETE CASCADE,
            expira_em INTEGER NOT NULL
        );
    ''')
    colunas = [r['name'] for r in con.execute('PRAGMA table_info(usuarios)')]
    if 'admin' not in colunas:
        con.execute('ALTER TABLE usuarios ADD COLUMN admin INTEGER NOT NULL DEFAULT 0')
    # sempre existe pelo menos um administrador: o usuário mais antigo
    if not con.execute('SELECT 1 FROM usuarios WHERE admin=1').fetchone():
        con.execute('UPDATE usuarios SET admin=1 WHERE usuario=(SELECT usuario FROM usuarios ORDER BY criado_em LIMIT 1)')
    con.close()


def agora_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

# ================= SENHAS E SESSÕES =================
def hash_senha(senha):
    sal = secrets.token_bytes(16)
    h = hashlib.scrypt(senha.encode(), salt=sal, n=2 ** 14, r=8, p=1, dklen=32)
    return 'scrypt$%s$%s' % (sal.hex(), h.hex())


def confere_senha(senha, guardado):
    try:
        _, sal, h = guardado.split('$')
        calc = hashlib.scrypt(senha.encode(), salt=bytes.fromhex(sal), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(calc.hex(), h)
    except Exception:
        return False


# hash fixo para gastar o mesmo tempo quando o usuário não existe
HASH_FALSO = hash_senha(secrets.token_hex(8))


def hash_token(t):
    return hashlib.sha256(t.encode()).hexdigest()


NOME_VALIDO = re.compile(r'^[a-z0-9._-]{3,32}$')


def valida_nome(nome):
    nome = str(nome or '').strip().lower()
    if not NOME_VALIDO.match(nome):
        raise ValueError('Usuário deve ter de 3 a 32 caracteres: letras minúsculas, números, ponto, hífen ou sublinhado.')
    return nome


def valida_senha(senha):
    senha = str(senha or '')
    if len(senha) < 8:
        raise ValueError('A senha precisa ter pelo menos 8 caracteres.')
    if len(senha) > 200:
        raise ValueError('Senha muito longa.')
    return senha


_falhas = {}
_falhas_lock = threading.Lock()


def login_bloqueado(ip):
    with _falhas_lock:
        agora = time.time()
        lst = [t for t in _falhas.get(ip, []) if agora - t < LOGIN_JANELA]
        _falhas[ip] = lst
        return len(lst) >= LOGIN_MAX_FALHAS


def registra_falha(ip):
    with _falhas_lock:
        _falhas.setdefault(ip, []).append(time.time())

# ================= HTTP =================
class Handler(BaseHTTPRequestHandler):
    server_version = 'SatimarAPI'
    sys_version = ''

    def log_message(self, fmt, *args):
        sys.stderr.write('%s %s\n' % (self.ip(), fmt % args))

    def ip(self):
        return self.headers.get('X-Real-IP') or self.client_address[0]

    def responde(self, status, corpo=None, cookie=None):
        dados = json.dumps(corpo if corpo is not None else {}, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(dados)))
        if cookie is not None:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(dados)

    def le_json(self):
        if not (self.headers.get('Content-Type') or '').startswith('application/json'):
            raise ValueError('Content-Type deve ser application/json')
        n = int(self.headers.get('Content-Length') or 0)
        if n > MAX_BODY:
            raise ValueError('Dados muito grandes')
        return json.loads(self.rfile.read(n) or b'{}')

    def cookie_sessao(self, token, max_age):
        c = '%s=%s; Path=/api/; HttpOnly; SameSite=Strict; Max-Age=%d' % (COOKIE, token, max_age)
        return c + ('; Secure' if COOKIE_SECURE else '')

    def token_atual(self):
        c = SimpleCookie(self.headers.get('Cookie') or '')
        return c[COOKIE].value if COOKIE in c else None

    def usuario_logado(self, con):
        token = self.token_atual()
        if not token:
            return None
        row = con.execute('SELECT s.usuario, s.expira_em, u.admin FROM sessoes s '
                          'JOIN usuarios u ON u.usuario = s.usuario WHERE s.token_hash=?',
                          (hash_token(token),)).fetchone()
        if not row or row['expira_em'] < time.time():
            return None
        return {'usuario': row['usuario'], 'admin': bool(row['admin'])}

    def rota(self, metodo):
        caminho = self.path.split('?', 1)[0]
        con = conectar()
        try:
            if metodo == 'POST' and caminho == '/api/login':
                return self.login(con)
            if metodo == 'POST' and caminho == '/api/logout':
                return self.logout(con)
            usuario = self.usuario_logado(con)
            if not usuario:
                return self.responde(401, {'erro': 'Faça login para continuar.'})
            if metodo == 'GET' and caminho == '/api/me':
                return self.responde(200, usuario)
            if metodo == 'GET' and caminho == '/api/estado':
                return self.get_estado(con)
            if metodo == 'PUT' and caminho == '/api/estado':
                return self.put_estado(con, usuario['usuario'])
            if metodo == 'POST' and caminho == '/api/senha':
                return self.trocar_senha(con, usuario['usuario'])
            if caminho.startswith('/api/usuarios'):
                if not usuario['admin']:
                    return self.responde(403, {'erro': 'Apenas administradores podem gerenciar usuários.'})
                if metodo == 'GET' and caminho == '/api/usuarios':
                    return self.listar_usuarios(con)
                if metodo == 'POST' and caminho == '/api/usuarios':
                    return self.criar_usuario(con)
                if metodo == 'POST' and caminho == '/api/usuarios/redefinir':
                    return self.redefinir_senha(con)
                if metodo == 'POST' and caminho == '/api/usuarios/remover':
                    return self.remover_usuario(con, usuario['usuario'])
            return self.responde(404, {'erro': 'Rota não encontrada.'})
        except ValueError as e:
            return self.responde(400, {'erro': str(e)})
        except Exception as e:
            sys.stderr.write('ERRO: %r\n' % e)
            return self.responde(500, {'erro': 'Erro interno no servidor.'})
        finally:
            con.close()

    def do_GET(self):
        self.rota('GET')

    def do_POST(self):
        self.rota('POST')

    def do_PUT(self):
        self.rota('PUT')

    def login(self, con):
        ip = self.ip()
        if login_bloqueado(ip):
            return self.responde(429, {'erro': 'Muitas tentativas. Aguarde 15 minutos.'})
        corpo = self.le_json()
        usuario = str(corpo.get('usuario') or '').strip().lower()
        senha = str(corpo.get('senha') or '')
        row = con.execute('SELECT senha_hash FROM usuarios WHERE usuario=?', (usuario,)).fetchone()
        ok = confere_senha(senha, row['senha_hash'] if row else HASH_FALSO) and row is not None
        if not ok:
            registra_falha(ip)
            return self.responde(401, {'erro': 'Usuário ou senha inválidos.'})
        token = secrets.token_urlsafe(32)
        con.execute('DELETE FROM sessoes WHERE expira_em < ?', (int(time.time()),))
        con.execute('INSERT INTO sessoes (token_hash, usuario, expira_em) VALUES (?,?,?)',
                    (hash_token(token), usuario, int(time.time()) + SESSAO_DIAS * 86400))
        admin = bool(con.execute('SELECT admin FROM usuarios WHERE usuario=?', (usuario,)).fetchone()['admin'])
        return self.responde(200, {'usuario': usuario, 'admin': admin}, self.cookie_sessao(token, SESSAO_DIAS * 86400))

    def logout(self, con):
        c = SimpleCookie(self.headers.get('Cookie') or '')
        if COOKIE in c:
            con.execute('DELETE FROM sessoes WHERE token_hash=?', (hash_token(c[COOKIE].value),))
        return self.responde(200, {}, self.cookie_sessao('', 0))

    def trocar_senha(self, con, usuario):
        ip = self.ip()
        if login_bloqueado(ip):
            return self.responde(429, {'erro': 'Muitas tentativas. Aguarde 15 minutos.'})
        corpo = self.le_json()
        row = con.execute('SELECT senha_hash FROM usuarios WHERE usuario=?', (usuario,)).fetchone()
        if not confere_senha(str(corpo.get('senha_atual') or ''), row['senha_hash']):
            registra_falha(ip)
            return self.responde(400, {'erro': 'A senha atual está incorreta.'})
        nova = valida_senha(corpo.get('nova_senha'))
        con.execute('UPDATE usuarios SET senha_hash=? WHERE usuario=?', (hash_senha(nova), usuario))
        # encerra as sessões em outros aparelhos, mantém a atual
        con.execute('DELETE FROM sessoes WHERE usuario=? AND token_hash<>?',
                    (usuario, hash_token(self.token_atual() or '')))
        return self.responde(200, {'ok': True})

    def listar_usuarios(self, con):
        rows = con.execute('SELECT usuario, admin, criado_em FROM usuarios ORDER BY usuario').fetchall()
        return self.responde(200, {'usuarios': [{'usuario': r['usuario'], 'admin': bool(r['admin']),
                                                 'criado_em': r['criado_em']} for r in rows]})

    def criar_usuario(self, con):
        corpo = self.le_json()
        nome = valida_nome(corpo.get('usuario'))
        senha = valida_senha(corpo.get('senha'))
        if con.execute('SELECT 1 FROM usuarios WHERE usuario=?', (nome,)).fetchone():
            return self.responde(409, {'erro': 'Já existe um usuário com esse nome.'})
        con.execute('INSERT INTO usuarios (usuario, senha_hash, criado_em, admin) VALUES (?,?,?,?)',
                    (nome, hash_senha(senha), agora_iso(), 1 if corpo.get('admin') else 0))
        return self.responde(201, {'usuario': nome})

    def redefinir_senha(self, con):
        corpo = self.le_json()
        nome = valida_nome(corpo.get('usuario'))
        senha = valida_senha(corpo.get('senha'))
        n = con.execute('UPDATE usuarios SET senha_hash=? WHERE usuario=?', (hash_senha(senha), nome)).rowcount
        if not n:
            return self.responde(404, {'erro': 'Usuário não encontrado.'})
        con.execute('DELETE FROM sessoes WHERE usuario=?', (nome,))
        return self.responde(200, {'ok': True})

    def remover_usuario(self, con, quem):
        nome = valida_nome(self.le_json().get('usuario'))
        if nome == quem:
            return self.responde(400, {'erro': 'Você não pode remover o seu próprio usuário.'})
        if not con.execute('DELETE FROM usuarios WHERE usuario=?', (nome,)).rowcount:
            return self.responde(404, {'erro': 'Usuário não encontrado.'})
        return self.responde(200, {'ok': True})

    def get_estado(self, con):
        row = con.execute('SELECT * FROM estado WHERE id=1').fetchone()
        if not row:
            return self.responde(200, {'versao': 0, 'dados': None})
        return self.responde(200, {'versao': row['versao'], 'dados': json.loads(row['dados']),
                                   'atualizado_em': row['atualizado_em'],
                                   'atualizado_por': row['atualizado_por']})

    def put_estado(self, con, usuario):
        corpo = self.le_json()
        dados = corpo.get('dados')
        versao = corpo.get('versao')
        if not isinstance(versao, int):
            raise ValueError('Versão inválida.')
        if not isinstance(dados, dict) or not isinstance(dados.get('funcionarios'), list):
            raise ValueError('Dados inválidos: falta a lista de funcionários.')
        for k in ('treinamentos', 'asos', 'vacinas'):
            if not isinstance(dados.get(k, []), list):
                raise ValueError('Dados inválidos: %s deve ser uma lista.' % k)
        texto = json.dumps(dados, ensure_ascii=False)
        quando = agora_iso()
        con.execute('BEGIN IMMEDIATE')
        try:
            row = con.execute('SELECT versao, atualizado_por, atualizado_em FROM estado WHERE id=1').fetchone()
            atual = row['versao'] if row else 0
            if versao != atual:
                con.execute('ROLLBACK')
                return self.responde(409, {'erro': 'Os dados foram alterados por outra pessoa.',
                                           'versao': atual,
                                           'atualizado_por': row['atualizado_por'] if row else None,
                                           'atualizado_em': row['atualizado_em'] if row else None})
            nova = atual + 1
            con.execute('INSERT INTO estado (id, dados, versao, atualizado_em, atualizado_por) VALUES (1,?,?,?,?) '
                        'ON CONFLICT(id) DO UPDATE SET dados=excluded.dados, versao=excluded.versao, '
                        'atualizado_em=excluded.atualizado_em, atualizado_por=excluded.atualizado_por',
                        (texto, nova, quando, usuario))
            con.execute('INSERT INTO historico (versao, dados, salvo_em, salvo_por) VALUES (?,?,?,?)',
                        (nova, texto, quando, usuario))
            con.execute('DELETE FROM historico WHERE id <= (SELECT MAX(id) FROM historico) - ?', (HISTORICO_MAX,))
            con.execute('COMMIT')
        except Exception:
            con.execute('ROLLBACK')
            raise
        return self.responde(200, {'versao': nova, 'atualizado_em': quando, 'atualizado_por': usuario})

# ================= LINHA DE COMANDO =================
def cmd_criar_usuario(nome):
    nome = nome.strip().lower()
    if not nome:
        sys.exit('Informe o nome do usuário.')
    s1 = getpass.getpass('Senha para %s: ' % nome)
    if len(s1) < 8:
        sys.exit('A senha precisa ter pelo menos 8 caracteres.')
    if getpass.getpass('Repita a senha: ') != s1:
        sys.exit('As senhas não conferem.')
    con = conectar()
    con.execute('INSERT INTO usuarios (usuario, senha_hash, criado_em) VALUES (?,?,?) '
                'ON CONFLICT(usuario) DO UPDATE SET senha_hash=excluded.senha_hash',
                (nome, hash_senha(s1), agora_iso()))
    con.execute('DELETE FROM sessoes WHERE usuario=?', (nome,))
    con.close()
    print('Usuário "%s" salvo.' % nome)


def cmd_remover_usuario(nome):
    con = conectar()
    n = con.execute('DELETE FROM usuarios WHERE usuario=?', (nome.strip().lower(),)).rowcount
    con.close()
    print('Usuário removido.' if n else 'Usuário não encontrado.')


def cmd_listar_usuarios():
    con = conectar()
    for r in con.execute('SELECT usuario, criado_em FROM usuarios ORDER BY usuario'):
        print('%s  (criado em %s)' % (r['usuario'], r['criado_em']))
    con.close()


def cmd_backup(pasta):
    os.makedirs(pasta, exist_ok=True)
    destino = os.path.join(pasta, 'satimar-%s.db' % datetime.now().strftime('%Y%m%d-%H%M%S'))
    origem = conectar()
    copia = sqlite3.connect(destino)
    origem.backup(copia)
    copia.close()
    origem.close()
    arquivos = sorted(f for f in os.listdir(pasta) if f.startswith('satimar-') and f.endswith('.db'))
    for velho in arquivos[:-30]:
        os.remove(os.path.join(pasta, velho))
    print('Backup salvo em', destino)


def main():
    criar_tabelas()
    args = sys.argv[1:]
    if not args:
        srv = ThreadingHTTPServer((HOST, PORT), Handler)
        print('API Satimar ouvindo em %s:%d (banco: %s)' % (HOST, PORT, DB_PATH), flush=True)
        srv.serve_forever()
    elif args[0] == 'criar-usuario' and len(args) == 2:
        cmd_criar_usuario(args[1])
    elif args[0] == 'remover-usuario' and len(args) == 2:
        cmd_remover_usuario(args[1])
    elif args[0] == 'listar-usuarios':
        cmd_listar_usuarios()
    elif args[0] == 'backup' and len(args) == 2:
        cmd_backup(args[1])
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main()
