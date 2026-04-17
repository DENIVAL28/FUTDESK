import sqlite3
import functools
import os
import shutil
import random
import secrets
import tempfile
import string
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, g, request, redirect, url_for, flash, session
)
from werkzeug.security import check_password_hash, generate_password_hash

# --- CONFIGURAÇÃO ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'dados_usuarios')
USER_DB_PATH = os.path.join(BASE_DIR, 'users.db')

if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

CATEGORIAS_DISPONIVEIS = ['ABERTO', 'VETERANOS', 'FEMININO']
ARQUIVOS_LEGADO = {
    'ABERTO': os.path.join(BASE_DIR, 'aberto.db'),
    'VETERANOS': os.path.join(BASE_DIR, 'veteranos.db'),
    'FEMININO': os.path.join(BASE_DIR, 'feminino.db')
}

app = Flask(__name__)

# --- SEGURANÇA BÁSICA ---
# Defina uma chave fixa via variável de ambiente para produção:
#   FUTEDESK_SECRET_KEY="uma-chave-longa-e-aleatoria"
# Se não estiver definida, o sistema gera uma chave aleatória (sessões serão invalidadas a cada restart).
_secret_from_env = os.environ.get("FUTEDESK_SECRET_KEY")
if _secret_from_env and len(_secret_from_env.strip()) >= 32:
    app.secret_key = _secret_from_env.strip()
else:
    app.secret_key = secrets.token_hex(32)
    print("AVISO: FUTEDESK_SECRET_KEY não definida (ou curta). "
          "Usando chave aleatória nesta execução. Para produção, defina FUTEDESK_SECRET_KEY.")

# Cookies de sessão mais seguros (compatível com a maioria dos navegadores)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Se você estiver usando HTTPS, ative secure cookie com:
#   FUTEDESK_COOKIE_SECURE=1
if os.environ.get("FUTEDESK_COOKIE_SECURE", "0") == "1":
    app.config["SESSION_COOKIE_SECURE"] = True

# Limite de upload (evita arquivo gigante)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB


def formatar_data_br(data_iso):
    if not data_iso:
        return ""
    try:
        data_obj = datetime.strptime(str(data_iso).split()[0], '%Y-%m-%d')
        return data_obj.strftime('%d/%m/%Y')
    except:
        return str(data_iso)


app.jinja_env.filters['formatar_data_br'] = formatar_data_br


class User:
    def __init__(
        self, id, username, password_hash, is_admin, validade_licenca, is_vitalicio,
        nome_campeonato=None, categorias_permitidas=None, whatsapp_number=None,
        postar_no_mural=0, tipo_campeonato='CORRIDOS'
    ):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = is_admin
        self.validade_licenca = validade_licenca
        self.is_vitalicio = is_vitalicio
        self.nome_campeonato = nome_campeonato
        self.whatsapp_number = whatsapp_number
        self.postar_no_mural = postar_no_mural
        self.tipo_campeonato = tipo_campeonato

        if categorias_permitidas and categorias_permitidas.strip():
            self.categorias_permitidas = categorias_permitidas.split(',')
        else:
            self.categorias_permitidas = CATEGORIAS_DISPONIVEIS

    @property
    def dias_restantes(self):
        if self.is_vitalicio or self.is_admin:
            return 9999
        if not self.validade_licenca:
            return 0
        try:
            return (datetime.fromisoformat(self.validade_licenca) - datetime.now()).days
        except:
            return 0


def validar_senha_forte(senha):
    return len(senha) >= 8


def init_db_migration():
    try:
        with sqlite3.connect(USER_DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                "CREATE TABLE IF NOT EXISTS users ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "username TEXT UNIQUE, "
                "password_hash TEXT, "
                "is_admin INTEGER, "
                "validade_licenca TEXT, "
                "is_vitalicio INTEGER DEFAULT 0)"
            )
            c.execute("CREATE TABLE IF NOT EXISTS config (chave TEXT UNIQUE, valor TEXT)")
            c.execute("INSERT OR IGNORE INTO config (chave, valor) VALUES ('preco_mensal', '120')")
            c.execute("INSERT OR IGNORE INTO config (chave, valor) VALUES ('preco_vitalicio', '1.400')")

            c.execute("PRAGMA table_info(users)")
            cols = [i[1] for i in c.fetchall()]

            if 'validade_licenca' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN validade_licenca TEXT")
            if 'is_vitalicio' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN is_vitalicio INTEGER DEFAULT 0")
            if 'nome_campeonato' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN nome_campeonato TEXT")
            if 'categorias_permitidas' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN categorias_permitidas TEXT")
            if 'whatsapp_number' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN whatsapp_number TEXT")
            if 'postar_no_mural' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN postar_no_mural INTEGER DEFAULT 0")
            if 'tipo_campeonato' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN tipo_campeonato TEXT DEFAULT 'CORRIDOS'")

            conn.commit()
    except Exception as e:
        print(f"Erro DB Users: {e}")


init_db_migration()


def get_user_db():
    db = getattr(g, '_user_database', None)
    if db is None:
        db = g._user_database = sqlite3.connect(USER_DB_PATH, timeout=10)
        db.row_factory = sqlite3.Row
    return db


def get_config(key, default_val):
    try:
        val = get_user_db().execute("SELECT valor FROM config WHERE chave=?", (key,)).fetchone()
        return val[0] if val else default_val
    except:
        return default_val



def _has_any_admin():
    """Retorna True se já existir algum admin cadastrado."""
    try:
        row = get_user_db().execute("SELECT 1 FROM users WHERE is_admin=1 LIMIT 1").fetchone()
        return bool(row)
    except Exception:
        return False


def _is_safe_subpath(base_dir: str, target_path: str) -> bool:
    """Evita path traversal: garante que target_path está dentro de base_dir."""
    try:
        base = os.path.realpath(base_dir)
        target = os.path.realpath(target_path)
        return os.path.commonpath([base]) == os.path.commonpath([base, target])
    except Exception:
        return False


def _validate_sqlite_db_file(db_path: str) -> tuple[bool, str]:
    """Valida minimamente se o arquivo parece um DB do sistema (tabelas esperadas)."""
    required_tables = {"times", "confrontos", "artilharia", "goleiros", "folgas"}
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cur.fetchall()}
        conn.close()
        missing = required_tables - tables
        if missing:
            return False, f"DB inválido: faltando tabelas {sorted(missing)}"
        return True, "OK"
    except Exception as e:
        return False, f"DB inválido: {e}"

def init_category_tables(db_conn):
    c = db_conn.cursor()
    c.execute(
        'CREATE TABLE IF NOT EXISTS times ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT, '
        'rodada_num INTEGER, '
        'nome TEXT, '
        'logo_url TEXT, '
        'V INTEGER DEFAULT 0, '
        'E INTEGER DEFAULT 0, '
        'D INTEGER DEFAULT 0, '
        'GM INTEGER DEFAULT 0, '
        'GS INTEGER DEFAULT 0, '
        'grupo TEXT DEFAULT "A", '
        'modo_disputa TEXT DEFAULT "LEAGUE")'
    )
    c.execute(
        'CREATE TABLE IF NOT EXISTS confrontos ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT, '
        'rodada_num INTEGER, '
        'data_confronto TEXT, '
        'horario TEXT, '
        'local TEXT, '
        'jogo_num TEXT, '
        'time_a TEXT, '
        'time_b TEXT, '
        'modo_disputa TEXT DEFAULT "LEAGUE", '
        'divulgar_mural INTEGER DEFAULT 0)'
    )
    c.execute(
        'CREATE TABLE IF NOT EXISTS artilharia ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT, '
        'rodada_num INTEGER, '
        'jogador TEXT, '
        'time_nome TEXT, '
        'camisa INTEGER, '
        'gols INTEGER)'
    )
    c.execute(
        'CREATE TABLE IF NOT EXISTS goleiros ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT, '
        'rodada_num INTEGER, '
        'jogador TEXT, '
        'time_nome TEXT, '
        'camisa INTEGER, '
        'gols_sofridos INTEGER)'
    )
    c.execute(
        'CREATE TABLE IF NOT EXISTS folgas ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT, '
        'rodada_num INTEGER, '
        'time_nome TEXT)'
    )

    c.execute("PRAGMA table_info(times)")
    cols_times = [info[1] for info in c.fetchall()]
    if 'grupo' not in cols_times:
        c.execute("ALTER TABLE times ADD COLUMN grupo TEXT DEFAULT 'A'")
    if 'modo_disputa' not in cols_times:
        c.execute("ALTER TABLE times ADD COLUMN modo_disputa TEXT DEFAULT 'LEAGUE'")
    if 'logo_url' not in cols_times:
        c.execute("ALTER TABLE times ADD COLUMN logo_url TEXT")

    c.execute("PRAGMA table_info(confrontos)")
    cols_conf = [info[1] for info in c.fetchall()]
    if 'modo_disputa' not in cols_conf:
        c.execute("ALTER TABLE confrontos ADD COLUMN modo_disputa TEXT DEFAULT 'LEAGUE'")
    if 'divulgar_mural' not in cols_conf:
        c.execute("ALTER TABLE confrontos ADD COLUMN divulgar_mural INTEGER DEFAULT 0")

    db_conn.commit()


def get_category_db():
    name = session.get('current_category_db')
    if not name:
        return None
    path = os.path.join(DATA_DIR, name)
    db = getattr(g, '_category_database', None)
    if db is None:
        if not os.path.exists(DATA_DIR):
            os.makedirs(DATA_DIR)
        db = g._category_database = sqlite3.connect(path, timeout=10)
        db.execute("PRAGMA foreign_keys = ON")
        db.row_factory = sqlite3.Row
        init_category_tables(db)
    return db


def current_modo():
    # Separa TUDO por modo: COPA (CUP) e LIGA (LEAGUE)
    if g.user and g.user.tipo_campeonato == 'MATA_MATA':
        return 'CUP'
    return 'LEAGUE'


def get_rodadas_salvas(db):
    if not db:
        return []
    try:
        modo = current_modo()
        return [dict(r) for r in db.execute(
            'SELECT DISTINCT rodada_num FROM times WHERE modo_disputa=? ORDER BY rodada_num ASC',
            [modo]
        ).fetchall()]
    except:
        return []


def get_classificacao(db, r):
    if not db:
        return []
    modo_atual = current_modo()

    try:
        t = [dict(row) for row in db.execute(
            'SELECT * FROM times WHERE rodada_num=? AND modo_disputa=?', [r, modo_atual]
        ).fetchall()]
    except:
        init_category_tables(db)
        t = []

    for team in t:
        try:
            v = int(team['V']) if team['V'] is not None else 0
            e = int(team['E']) if team['E'] is not None else 0
            d = int(team['D']) if team['D'] is not None else 0
            gm = int(team['GM']) if team['GM'] is not None else 0
            gs = int(team['GS']) if team['GS'] is not None else 0
        except:
            v = e = d = gm = gs = 0

        team['V'] = v
        team['E'] = e
        team['D'] = d
        team['GM'] = gm
        team['GS'] = gs
        team['P'] = (v * 3) + e
        team['J'] = v + e + d
        team['SG'] = gm - gs

    return sorted(t, key=lambda x: (x['P'], x['GM'], -x['GS'], x['SG']), reverse=True)


def _duplicar_rodada_logica(db, old, new):
    init_category_tables(db)
    try:
        for t in db.execute('SELECT * FROM times WHERE rodada_num=?', [old]).fetchall():
            db.execute(
                'INSERT INTO times (rodada_num,nome,logo_url,V,E,D,GM,GS,grupo,modo_disputa) '
                'VALUES (?,?,?,?,?,?,?,?,?,?)',
                (new, t['nome'], t['logo_url'], t['V'], t['E'], t['D'], t['GM'], t['GS'], t['grupo'], t['modo_disputa'])
            )
        db.commit()
        return True, None
    except Exception as e:
        db.rollback()
        return False, f"Erro: {e}"


def gerar_tabela_jogos_logica(teams):
    teams_copy = list(teams)
    if len(teams_copy) % 2 != 0:
        teams_copy.append("FOLGA")
    n = len(teams_copy)
    rodadas_list = []

    for i in range(n - 1):
        rodada_atual = []
        for j in range(n // 2):
            t1 = teams_copy[j]
            t2 = teams_copy[n - 1 - j]
            if t1 == "FOLGA":
                rodada_atual.append((t2, "Folga"))
            elif t2 == "FOLGA":
                rodada_atual.append((t1, "Folga"))
            else:
                rodada_atual.append((t1, t2))
        rodadas_list.append(rodada_atual)
        teams_copy.insert(1, teams_copy.pop())

    return rodadas_list


def get_artilharia(db, rodada_num):
    return [dict(row) for row in db.execute(
        "SELECT * FROM artilharia WHERE rodada_num = ? ORDER BY gols DESC", [rodada_num]
    ).fetchall()]


def get_goleiros(db, rodada_num):
    return [dict(row) for row in db.execute(
        "SELECT * FROM goleiros WHERE rodada_num = ? ORDER BY gols_sofridos ASC", [rodada_num]
    ).fetchall()]


def get_confrontos(db, rodada_num):
    modo_atual = current_modo()
    try:
        return [dict(row) for row in db.execute(
            'SELECT * FROM confrontos WHERE rodada_num = ? AND modo_disputa = ? '
            'ORDER BY jogo_num ASC, data_confronto ASC',
            [rodada_num, modo_atual]
        ).fetchall()]
    except:
        return []


def get_folgas(db, rodada_num):
    return [dict(row) for row in db.execute(
        "SELECT * FROM folgas WHERE rodada_num = ? ORDER BY time_nome", [rodada_num]
    ).fetchall()]


def get_all_teams(db, r):
    modo = current_modo()
    return [dict(row) for row in db.execute(
        'SELECT id, nome, grupo FROM times WHERE rodada_num=? AND modo_disputa=? ORDER BY nome',
        [r, modo]
    ).fetchall()]


# ✅ CORRIGIDO: agora separa CUP/LEAGUE
def get_team_by_id(db, id, r):
    modo = current_modo()
    row = db.execute(
        'SELECT * FROM times WHERE id=? AND rodada_num=? AND modo_disputa=?',
        [id, r, modo]
    ).fetchone()
    return dict(row) if row else None


# ✅ CORRIGIDO: agora separa CUP/LEAGUE
def get_confronto_by_id(db, id, r):
    modo = current_modo()
    row = db.execute(
        'SELECT * FROM confrontos WHERE id = ? AND rodada_num = ? AND modo_disputa = ?',
        [id, r, modo]
    ).fetchone()
    return dict(row) if row else None


@app.teardown_appcontext
def close_connections(exception):
    if getattr(g, '_user_database', None):
        g._user_database.close()
    if getattr(g, '_category_database', None):
        g._category_database.close()


@app.before_request
def load_user():
    uid = session.get('user_id')
    g.user = None
    if uid:
        try:
            r = get_user_db().execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
            if r:
                d = dict(zip(r.keys(), r))
                nc = d.get('nome_campeonato')
                cats = d.get('categorias_permitidas')
                wa = d.get('whatsapp_number')
                pm = d.get('postar_no_mural', 0)
                tp = d.get('tipo_campeonato', 'CORRIDOS')
                g.user = User(
                    d['id'], d['username'], d['password_hash'], d['is_admin'],
                    d.get('validade_licenca'), d.get('is_vitalicio', 0),
                    nc, cats, wa, pm, tp
                )
        except Exception as e:
            print(f"Erro load_user: {e}")


def login_required(view):
    @functools.wraps(view)
    def wrapped(**kwargs):
        if not g.user:
            return redirect(url_for('login'))
        exempt = [
            'selecionar_categoria', 'set_categoria', 'logout', 'index_publico',
            'publico_lista_campeonatos', 'publico_selecionar', 'publico_ver_tabela',
            'fase_grupos_page', 'alterar_modo_campeonato'
        ]
        if request.endpoint in exempt:
            return view(**kwargs)
        if 'current_category_db' not in session:
            return redirect(url_for('selecionar_categoria'))
        if 'current_rodada_num' not in session and request.endpoint not in ['index', 'carregar_rodada', 'admin_page', 'destravar_modo']:
            return redirect(url_for('index'))
        return view(**kwargs)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(**kwargs):
        if not g.user or not g.user.is_admin:
            flash("Apenas Admin.", "error")
            return redirect(url_for('index'))
        return view(**kwargs)
    return wrapped


def verificar_licenca(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user or g.user.is_admin or g.user.is_vitalicio:
            return f(*args, **kwargs)
        if g.user.validade_licenca:
            try:
                if datetime.now() > datetime.fromisoformat(g.user.validade_licenca):
                    return render_template('sem_licenca.html')
            except:
                pass
        return f(*args, **kwargs)
    return decorated_function


@app.route('/imprimir_classificacao_old')
def imprimir_classificacao_old():
    return redirect(url_for('index'))


@app.route('/publico/campeonatos')
def publico_lista_campeonatos():
    try:
        users = get_user_db().execute(
            'SELECT id, username, nome_campeonato, categorias_permitidas, postar_no_mural FROM users'
        ).fetchall()
        campeonatos = []
        for u in users:
            if u['postar_no_mural'] == 1:
                display_name = u['nome_campeonato'] if u['nome_campeonato'] and u['nome_campeonato'].strip() else u['username'].upper()
                cats = u['categorias_permitidas'].split(',') if u['categorias_permitidas'] else ['ABERTO']
                campeonatos.append({'id': u['id'], 'nome': display_name, 'categorias': cats})
        return render_template('public_list.html', campeonatos=campeonatos, jogos=[])
    except Exception as e:
        return f"Erro: {e}"


@app.route('/publico/selecionar/<int:user_id>')
def publico_selecionar(user_id):
    user_row = get_user_db().execute('SELECT * FROM users WHERE id=?', [user_id]).fetchone()
    if not user_row:
        return "Usuário não encontrado", 404
    u_dict = dict(user_row)
    temp_user = User(
        u_dict['id'], u_dict['username'], '', 0, None, 0,
        u_dict.get('nome_campeonato'), u_dict.get('categorias_permitidas'),
        u_dict.get('whatsapp_number'), u_dict.get('postar_no_mural', 0),
        u_dict.get('tipo_campeonato', 'CORRIDOS')
    )
    nome_exibicao = temp_user.nome_campeonato if temp_user.nome_campeonato and temp_user.nome_campeonato.strip() else temp_user.username.upper()
    return render_template('public_selection.html', user_id=user_id, nome_campeonato=nome_exibicao, categorias=temp_user.categorias_permitidas)


@app.route('/publico/ver/<int:user_id>/<categoria>')
def publico_ver_tabela(user_id, categoria):
    if categoria not in CATEGORIAS_DISPONIVEIS:
        return redirect(url_for('publico_lista_campeonatos'))
    user = get_user_db().execute('SELECT username, nome_campeonato, tipo_campeonato FROM users WHERE id=?', [user_id]).fetchone()
    if not user:
        return "Organizador não encontrado", 404
    modo_publico = 'LEAGUE'
    if 'tipo_campeonato' in user.keys() and user['tipo_campeonato'] == 'MATA_MATA':
        modo_publico = 'CUP'

    nome_exibicao = user['nome_campeonato'] if user['nome_campeonato'] and user['nome_campeonato'].strip() else user['username'].upper()
    db_name = f"user_{user_id}_{categoria.lower()}.db"
    db_path = os.path.join(DATA_DIR, db_name)

    if not os.path.exists(db_path):
        flash(f"A categoria {categoria} ainda não foi iniciada.", "error")
        return redirect(url_for('publico_selecionar', user_id=user_id))

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        init_category_tables(conn)
        rodadas = [dict(r) for r in conn.execute('SELECT DISTINCT rodada_num FROM times ORDER BY rodada_num ASC').fetchall()]
        rodada_atual = rodadas[-1]['rodada_num'] if rodadas else 1
        t_rows = conn.execute('SELECT * FROM times WHERE rodada_num=? AND modo_disputa=?', [rodada_atual, modo_publico]).fetchall()
        times = [dict(row) for row in t_rows]

        for team in times:
            try:
                v = int(team['V'] or 0)
                e = int(team['E'] or 0)
                d = int(team['D'] or 0)
                gm = int(team['GM'] or 0)
                gs = int(team['GS'] or 0)
            except:
                v = e = d = gm = gs = 0
            team['P'] = (v * 3) + e
            team['J'] = v + e + d
            team['SG'] = gm - gs

        times = sorted(times, key=lambda x: (x['P'], x['GM'], -x['GS'], x['SG']), reverse=True)
        conn.close()
        return render_template('public_view.html', times=times, categoria=categoria, rodada=rodada_atual, nome_campeonato=nome_exibicao, user_id=user_id)
    except Exception as e:
        return f"Erro: {e}"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('selecionar_categoria'))
    if request.method == 'POST':
        try:
            r = get_user_db().execute('SELECT * FROM users WHERE username=?', (request.form['username'],)).fetchone()
            if r and check_password_hash(r['password_hash'], request.form['password']):
                session.clear()
                session['user_id'] = r['id']
                return redirect(url_for('selecionar_categoria'))
        except Exception as e:
            print(e)
        flash('Usuário ou senha incorretos.', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if not g.user or not g.user.is_admin:
        return render_template('registro_fechado.html')
    if request.method == 'POST':
        senha = request.form['password']
        nome_camp = request.form.get('nome_campeonato', '').strip().upper()
        cats_selecionadas = request.form.getlist('categorias')
        cats_str = ",".join(cats_selecionadas) if cats_selecionadas else "ABERTO,VETERANOS,FEMININO"
        postar_mural = 1 if 'postar_no_mural' in request.form else 0
        tipo_camp = request.form.get('tipo_campeonato', 'CORRIDOS')

        if not validar_senha_forte(senha):
            flash('Senha fraca!', 'error')
            return render_template('register.html')

        bootstrap_admin = os.environ.get('FUTEDESK_BOOTSTRAP_ADMIN', 'denival').strip().lower()
        is_adm = 1 if (not _has_any_admin() and request.form['username'].strip().lower() == bootstrap_admin) else 0
        val = (datetime.now() + timedelta(days=10)).isoformat()

        try:
            get_user_db().execute(
                "INSERT INTO users (username,password_hash,is_admin,validade_licenca,is_vitalicio,nome_campeonato,categorias_permitidas, postar_no_mural, tipo_campeonato) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (request.form['username'], generate_password_hash(senha), is_adm, val, 0, nome_camp, cats_str, postar_mural, tipo_camp)
            )
            get_user_db().commit()
            flash('Usuário criado!', 'success')
            return redirect(url_for('admin_page'))
        except sqlite3.IntegrityError:
            flash('Usuário já existe!', 'error')
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index_publico'))


@app.route('/publico')
def index_publico():
    session.pop('current_category_db', None)
    return render_template('index_publico.html')


@app.route('/selecionar')
@login_required
def selecionar_categoria():
    cats = g.user.categorias_permitidas
    if not cats:
        flash('Você não tem categorias atribuídas.', 'error')
        return redirect(url_for('logout'))
    if len(cats) == 1:
        return redirect(url_for('set_categoria', nome_categoria=cats[0]))
    return render_template('selecionar_categoria.html', categorias_permitidas=cats)


@app.route('/set_categoria/<nome_categoria>')
@login_required
def set_categoria(nome_categoria):
    if nome_categoria not in g.user.categorias_permitidas:
        flash("Acesso negado.", "error")
        return redirect(url_for('selecionar_categoria'))

    user_db_name = f"user_{g.user.id}_{nome_categoria.lower()}.db"
    user_db_path = os.path.join(DATA_DIR, user_db_name)
    legacy_path = ARQUIVOS_LEGADO.get(nome_categoria)
    should_restore = False

    if not os.path.exists(user_db_path):
        should_restore = True
    else:
        try:
            c = sqlite3.connect(user_db_path)
            cur = c.cursor()
            cur.execute("SELECT count(*) FROM times")
            if cur.fetchone()[0] == 0:
                should_restore = True
            c.close()
        except:
            should_restore = True

    if should_restore and legacy_path and os.path.exists(legacy_path):
        try:
            shutil.copy(legacy_path, user_db_path)
        except:
            pass

    session['current_category_name'] = nome_categoria
    session['current_category_db'] = user_db_name
    session.pop('current_rodada_num', None)
    return redirect(url_for('index'))


@app.route('/index')
@login_required
def index():
    if g.user.tipo_campeonato == 'MATA_MATA':

        if 'current_rodada_num' not in session:
            session['current_rodada_num'] = 1
        return redirect(url_for('fase_grupos_page'))

    db = get_category_db()
    rodadas = get_rodadas_salvas(db)

    if not rodadas:
        session['current_rodada_num'] = 1
        return render_template('index.html', times=[], rodadas_salvas=[])

    if not session.get('current_rodada_num'):
        session['current_rodada_num'] = rodadas[-1]['rodada_num'] if rodadas else 1

    return render_template('index.html', times=get_classificacao(db, session['current_rodada_num']), rodadas_salvas=rodadas)


@app.route('/')
@login_required
def home():
    return redirect(url_for('index'))


@app.route('/carregar_rodada/<int:num>')
@login_required
def carregar_rodada(num):
    session['current_rodada_num'] = num
    return redirect(url_for('index'))


@app.route('/salvar_como_rodada', methods=['POST'])
@login_required
@verificar_licenca
def duplicar_rodada():
    new = int(request.form['nova_rodada_num'])
    _duplicar_rodada_logica(get_category_db(), session['current_rodada_num'], new)
    session['current_rodada_num'] = new
    return redirect(url_for('index'))


@app.route('/destravar_modo')
@login_required
def destravar_modo():
    get_user_db().execute("UPDATE users SET tipo_campeonato='CORRIDOS' WHERE id=?", (g.user.id,))
    get_user_db().commit()
    flash("SISTEMA DESTRAVADO! Você voltou para Pontos Corridos.", "success")
    return redirect(url_for('index'))


@app.route('/trocar_modo_rapido', methods=['POST'])
@login_required
def trocar_modo_rapido():
    # Rota obsoleta mantida para evitar erros se houver links antigos
    return redirect(url_for('index'))


@app.route('/deletar_rodada/<int:num>')
@login_required
def deletar_rodada(num):
    db = get_category_db()
    for t in ['times', 'artilharia', 'goleiros', 'confrontos', 'folgas']:
        db.execute(f'DELETE FROM {t} WHERE rodada_num=?', [num])
    db.commit()
    if session.get('current_rodada_num') == num:
        session.pop('current_rodada_num', None)
    return redirect(url_for('index'))


@app.route('/add_team', methods=['POST'])
@login_required
@verificar_licenca
def add_team():
    nome = request.form['nome_time'].strip().title()
    logo = request.form.get('logo_url', '')
    modo = current_modo()
    grupo = 'A'

    if modo == 'CUP':
        grupo = 'AGUARDANDO'

    grupo_form = request.form.get('grupo')
    if grupo_form and grupo_form != 'AGUARDANDO':
        grupo = grupo_form.upper()

    rodada = session.get('current_rodada_num', 1)
    session['current_rodada_num'] = rodada

    get_category_db().execute(
        'INSERT INTO times (nome,logo_url,rodada_num, grupo, modo_disputa) VALUES (?,?,?,?,?)',
        (nome, logo, rodada, grupo, modo)
    )
    get_category_db().commit()
    return redirect(url_for('fase_grupos_page' if g.user.tipo_campeonato == 'MATA_MATA' else 'index'))


@app.route('/edit/<int:id>')
@login_required
def edit_team(id):
    t = get_team_by_id(get_category_db(), id, session['current_rodada_num'])
    return render_template('edit_team.html', time=dict(t) if t else {})


@app.route('/update_team/<int:id>', methods=['POST'])
@login_required
def update_team(id):

    logo = request.form.get('logo_url', '')
    grupo = request.form.get('grupo', 'A').strip().upper()
    modo = current_modo()

    get_category_db().execute(
        'UPDATE times SET V=?,E=?,D=?,GM=?,GS=?,logo_url=?, grupo=? '
        'WHERE id=? AND rodada_num=? AND modo_disputa=?',
        (
            request.form['V'], request.form['E'], request.form['D'],
            request.form['GM'], request.form['GS'],
            logo, grupo,
            id, session['current_rodada_num'], modo
        )
    )
    get_category_db().commit()
    return redirect(url_for('fase_grupos_page' if g.user.tipo_campeonato == 'MATA_MATA' else 'index'))


@app.route('/delete_team/<int:id>')
@login_required
def delete_team(id):

    modo = current_modo()
    get_category_db().execute(
        'DELETE FROM times WHERE id=? AND rodada_num=? AND modo_disputa=?',
        [id, session['current_rodada_num'], modo]
    )
    get_category_db().commit()
    return redirect(url_for('fase_grupos_page' if g.user.tipo_campeonato == 'MATA_MATA' else 'index'))


@app.route('/artilharia')
@login_required
def artilharia_page():
    return render_template(
        'artilharia.html',
        artilheiros=get_artilharia(get_category_db(), session['current_rodada_num']),
        times=[t['nome'] for t in get_all_teams(get_category_db(), session['current_rodada_num'])]
    )


@app.route('/add_artilheiro', methods=['POST'])
@login_required
def add_artilheiro():
    get_category_db().execute(
        'INSERT INTO artilharia (rodada_num,jogador,time_nome,camisa,gols) VALUES (?,?,?,?,?)',
        (session['current_rodada_num'], request.form['jogador'], request.form['time_nome'], request.form['camisa'], request.form['gols'])
    )
    get_category_db().commit()
    return redirect(url_for('artilharia_page'))


@app.route('/artilharia/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_artilheiro(id):
    db = get_category_db()
    r = session['current_rodada_num']
    if request.method == 'POST':
        db.execute(
            'UPDATE artilharia SET jogador=?, time_nome=?, camisa=?, gols=? WHERE id=? AND rodada_num=?',
            (request.form['jogador'], request.form['time_nome'], request.form['camisa'], request.form['gols'], id, r)
        )
        db.commit()
        return redirect(url_for('artilharia_page'))
    row = db.execute('SELECT * FROM artilharia WHERE id=?', [id]).fetchone()
    times = [x['nome'] for x in get_all_teams(db, r)]
    return render_template('edit_artilheiro.html', artilheiro=dict(row) if row else {}, times=times)


@app.route('/delete_artilheiro/<int:id>')
@login_required
def delete_artilheiro(id):
    get_category_db().execute('DELETE FROM artilharia WHERE id=?', [id])
    get_category_db().commit()
    return redirect(url_for('artilharia_page'))


@app.route('/goleiros')
@login_required
def goleiros_page():
    return render_template(
        'goleiros.html',
        goleiros=get_goleiros(get_category_db(), session['current_rodada_num']),
        times=[t['nome'] for t in get_all_teams(get_category_db(), session['current_rodada_num'])]
    )


@app.route('/add_goleiro', methods=['POST'])
@login_required
def add_goleiro():
    get_category_db().execute(
        'INSERT INTO goleiros (rodada_num,jogador,time_nome,camisa,gols_sofridos) VALUES (?,?,?,?,?)',
        (session['current_rodada_num'], request.form['jogador'], request.form['time_nome'], request.form['camisa'], request.form['gols_sofridos'])
    )
    get_category_db().commit()
    return redirect(url_for('goleiros_page'))


@app.route('/goleiros/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_goleiro(id):
    db = get_category_db()
    r = session['current_rodada_num']
    if request.method == 'POST':
        db.execute(
            'UPDATE goleiros SET jogador=?, time_nome=?, camisa=?, gols_sofridos=? WHERE id=? AND rodada_num=?',
            (request.form['jogador'], request.form['time_nome'], request.form['camisa'], request.form['gols_sofridos'], id, r)
        )
        db.commit()
        return redirect(url_for('goleiros_page'))
    row = db.execute('SELECT * FROM goleiros WHERE id=?', [id]).fetchone()
    times = [x['nome'] for x in get_all_teams(db, r)]
    return render_template('edit_goleiro.html', goleiro=dict(row) if row else {}, times=times)


@app.route('/delete_goleiro/<int:id>')
@login_required
def delete_goleiro(id):
    get_category_db().execute('DELETE FROM goleiros WHERE id=?', [id])
    get_category_db().commit()
    return redirect(url_for('goleiros_page'))


@app.route('/confrontos')
@login_required
def confrontos_page():
    db = get_category_db()
    r = session.get('current_rodada_num', 1)
    return render_template(
        'confrontos.html',
        confrontos=get_confrontos(db, r),
        folgas=get_folgas(db, r),
        times_disponiveis=[t['nome'] for t in get_all_teams(db, r)]
    )


@app.route('/add_confronto', methods=['POST'])
@login_required
def add_confronto():
    modo = current_modo()
    data_raw = request.form.get('data_confronto')
    try:
        data_iso = datetime.strptime(data_raw, '%d/%m/%Y').strftime('%Y-%m-%d')
    except:
        data_iso = data_raw
    get_category_db().execute(
        'INSERT INTO confrontos (rodada_num,data_confronto,jogo_num,time_a,time_b,horario,local,modo_disputa) VALUES (?,?,?,?,?,?,?,?)',
        (session.get('current_rodada_num', 1), data_iso, request.form['jogo_num'], request.form['time_a'], request.form['time_b'], request.form['horario'], request.form['local'], modo)
    )
    get_category_db().commit()
    return redirect(url_for('confrontos_page'))


@app.route('/toggle_mural_jogo/<int:id>')
@login_required
def toggle_mural_jogo(id):
    db = get_category_db()
    row = db.execute("SELECT divulgar_mural FROM confrontos WHERE id=?", [id]).fetchone()
    if row:
        novo_status = 1 if row['divulgar_mural'] == 0 else 0
        db.execute("UPDATE confrontos SET divulgar_mural=? WHERE id=?", (novo_status, id))
        db.commit()
        if novo_status == 1:
            flash("Jogo PUBLICADO no Mural com sucesso!", "success")
        else:
            flash("Jogo REMOVIDO do Mural.", "info")
    return redirect(url_for('confrontos_page'))


@app.route('/confrontos/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_confronto(id):
    db = get_category_db()
    r = session['current_rodada_num']
    modo = current_modo()

    if request.method == 'POST':
        data_raw = request.form.get('data_confronto')
        try:
            data_iso = datetime.strptime(data_raw, '%d/%m/%Y').strftime('%Y-%m-%d')
        except:
            data_iso = data_raw

        db.execute(
            'UPDATE confrontos SET data_confronto=?, jogo_num=?, time_a=?, time_b=?, horario=?, local=? '
            'WHERE id=? AND rodada_num=? AND modo_disputa=?',
            (data_iso, request.form['jogo_num'], request.form['time_a'], request.form['time_b'], request.form['horario'], request.form['local'], id, r, modo)
        )
        db.commit()
        return redirect(url_for('confrontos_page'))

    confronto = get_confronto_by_id(db, id, r)
    return render_template('edit_confronto.html', confronto=confronto, times_nomes=[t['nome'] for t in get_all_teams(db, r)])


@app.route('/delete_confronto/<int:id>')
@login_required
def delete_confronto(id):

    modo = current_modo()
    get_category_db().execute(
        'DELETE FROM confrontos WHERE id=? AND rodada_num=? AND modo_disputa=?',
        [id, session.get('current_rodada_num', 1), modo]
    )
    get_category_db().commit()
    return redirect(url_for('confrontos_page'))


@app.route('/delete_all_confrontos')
@login_required
def delete_all_confrontos():
    db = get_category_db()
    r = session.get('current_rodada_num', 1)
    modo = current_modo()
    db.execute("DELETE FROM confrontos WHERE rodada_num=? AND modo_disputa=?", [r, modo])
    db.commit()
    flash("Todos os jogos foram excluídos com sucesso!", "success")
    return redirect(url_for('confrontos_page'))


@app.route('/add_folga', methods=['POST'])
@login_required
def add_folga():
    get_category_db().execute(
        'INSERT INTO folgas (rodada_num,time_nome) VALUES (?,?)',
        (session['current_rodada_num'], request.form['time_nome'])
    )
    get_category_db().commit()
    return redirect(url_for('confrontos_page'))


@app.route('/delete_folga/<int:id>')
@login_required
def delete_folga(id):
    get_category_db().execute('DELETE FROM folgas WHERE id=?', [id])
    get_category_db().commit()
    return redirect(url_for('confrontos_page'))


@app.route('/gerador', methods=['GET', 'POST'])
@login_required
def gerador_page():
    rodadas_output = None
    teams_input = None
    ida_volta = False
    if request.method == 'POST':
        raw_text = request.form.get('lista_times', '')
        ida_volta = 'ida_volta' in request.form
        teams_input = raw_text
        lista = [t.strip().title() for t in raw_text.splitlines() if t.strip()]
        if len(lista) < 2:
            flash('Adicione pelo menos 2 times.', 'error')
        else:
            try:
                turno = gerar_tabela_jogos_logica(lista)
                todas_rodadas = []
                todas_rodadas.extend(turno)
                if ida_volta:
                    returno = []
                    for rodada in turno:
                        rodada_returno = []
                        for confronto in rodada:
                            if confronto[1] != "Folga":
                                rodada_returno.append((confronto[1], confronto[0]))
                            else:
                                rodada_returno.append(confronto)
                        returno.append(rodada_returno)
                    todas_rodadas.extend(returno)
                rodadas_output = {i + 1: rodada for i, rodada in enumerate(todas_rodadas)}
            except Exception as e:
                flash(f'Erro interno: {e}', 'error')
    return render_template('gerador.html', rodadas=rodadas_output, teams_input=teams_input, ida_volta=ida_volta)


@app.route('/mata_mata')
@login_required
def mata_mata_page():
    times = get_classificacao(get_category_db(), session.get('current_rodada_num', 1))
    return render_template('mata_mata.html', times=times[:8])


@app.route('/fase_grupos')
@login_required
def fase_grupos_page():
    db = get_category_db()
    r = session.get('current_rodada_num', 1)
    try:
        times_com_grupo = [dict(row) for row in db.execute(
            "SELECT * FROM times WHERE rodada_num=? AND modo_disputa='CUP' AND grupo != 'AGUARDANDO'", [r]
        ).fetchall()]
        times_sem_grupo = [dict(row) for row in db.execute(
            "SELECT * FROM times WHERE rodada_num=? AND modo_disputa='CUP' AND grupo = 'AGUARDANDO'", [r]
        ).fetchall()]
    except:
        init_category_tables(db)
        times_com_grupo = []
        times_sem_grupo = []

    grupos = {}
    for time in times_com_grupo:
        try:
            v = int(time['V'] or 0)
            e = int(time['E'] or 0)
            d = int(time['D'] or 0)
            gm = int(time['GM'] or 0)
            gs = int(time['GS'] or 0)
        except:
            v = e = d = gm = gs = 0

        time['P'] = (v * 3) + e
        time['J'] = v + e + d
        time['SG'] = gm - gs
        g_letra = time['grupo']

        if g_letra not in grupos:
            grupos[g_letra] = []
        grupos[g_letra].append(time)

    for k in grupos:
        grupos[k] = sorted(grupos[k], key=lambda x: (x['P'], x['GM'], -x['GS'], x['SG']), reverse=True)

    qtd_times_grupos = sum(len(lista) for lista in grupos.values())
    total_times = len(times_sem_grupo) + qtd_times_grupos

    return render_template('fase_grupos.html', grupos=grupos, times_aguardando=times_sem_grupo, total_times=total_times)

@app.route('/sortear_grupos', methods=['POST'])
@login_required
def sortear_grupos():
    try:
        qtd_grupos = int(request.form.get('qtd_grupos', 4))
    except:
        qtd_grupos = 4

    # Limite de segurança
    if qtd_grupos < 1:
        qtd_grupos = 1
    if qtd_grupos > 10:
        qtd_grupos = 10

    db = get_category_db()

    # Garantir rodada na sessão
    r = session.get('current_rodada_num', 1)
    session['current_rodada_num'] = r

    # Buscar times do modo CUP
    times_db = db.execute(
        "SELECT id FROM times WHERE rodada_num=? AND modo_disputa='CUP'",
        [r]
    ).fetchall()

    ids_times = [t['id'] for t in times_db]

    if not ids_times:
        flash("Nenhum time cadastrado no modo Torneio para sortear!", "error")
        return redirect(url_for('fase_grupos_page'))

    # Impedir mais grupos que times
    if qtd_grupos > len(ids_times):
        flash("Não é possível ter mais grupos do que times!", "error")
        return redirect(url_for('fase_grupos_page'))

    random.shuffle(ids_times)

    letras = list(string.ascii_uppercase)[:qtd_grupos]

    for i, time_id in enumerate(ids_times):
        grupo_destino = letras[i % qtd_grupos]
        db.execute(
            "UPDATE times SET grupo=? WHERE id=? AND rodada_num=? AND modo_disputa='CUP'",
            (grupo_destino, time_id, r)
        )

    db.commit()

    flash(f"Sorteio realizado com {qtd_grupos} grupos!", "success")
    return redirect(url_for('fase_grupos_page'))

@app.route('/resetar_torneio', methods=['POST'])
@login_required
def resetar_torneio():
    acao = request.form.get('acao')
    db = get_category_db()
    r = session.get('current_rodada_num', 1)

    if acao == 'reset_sorteio':
        db.execute("UPDATE times SET grupo='AGUARDANDO' WHERE rodada_num=? AND modo_disputa='CUP'", [r])
        flash("Sorteio resetado! Todos os times voltaram para a espera.", "info")
    elif acao == 'excluir_tudo':
        db.execute("DELETE FROM times WHERE rodada_num=? AND modo_disputa='CUP'", [r])
        flash("Todos os times do torneio foram excluídos.", "warning")

    db.commit()
    return redirect(url_for('fase_grupos_page'))


@app.route('/gerar_jogos_grupos', methods=['POST'])
@login_required
def gerar_jogos_grupos():
    db = get_category_db()
    r = session.get('current_rodada_num', 1)
    times_db = db.execute(
        "SELECT id, nome, grupo FROM times WHERE rodada_num=? AND modo_disputa='CUP' AND grupo != 'AGUARDANDO'", [r]
    ).fetchall()

    grupos = {}
    for t in times_db:
        g_letra = t['grupo']
        if g_letra not in grupos:
            grupos[g_letra] = []
        grupos[g_letra].append(t['nome'])

    if not grupos:
        flash("Não há grupos formados para gerar jogos.", "error")
        return redirect(url_for('fase_grupos_page'))

    jogos_criados = 0
    for nome_grupo, lista_times in sorted(grupos.items()):
        n = len(lista_times)
        for i in range(n):
            for j in range(i + 1, n):
                time_a = lista_times[i]
                time_b = lista_times[j]
                descricao_jogo = f"GRP {nome_grupo}"
                db.execute(
                    'INSERT INTO confrontos (rodada_num, data_confronto, jogo_num, time_a, time_b, horario, local, modo_disputa) '
                    'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    (r, datetime.now().strftime('%Y-%m-%d'), descricao_jogo, time_a, time_b, "00:00", "Campo 1", "CUP")
                )
                jogos_criados += 1

    db.commit()
    flash(f"{jogos_criados} jogos gerados com sucesso! Vá para a tela de JOGOS.", "success")
    return redirect(url_for('confrontos_page'))


@app.route('/admin/toggle_publicar/<int:user_id>')
@login_required
@admin_required
def toggle_publicar(user_id):
    db = get_user_db()
    u = db.execute("SELECT postar_no_mural FROM users WHERE id=?", [user_id]).fetchone()
    if u:
        novo_status = 1 if u['postar_no_mural'] == 0 else 0
        db.execute("UPDATE users SET postar_no_mural=? WHERE id=?", (novo_status, user_id))
        db.commit()
        if novo_status:
            flash("Campeonato PUBLICADO no site.", "success")
        else:
            flash("Campeonato REMOVIDO do site.", "info")
    return redirect(url_for('admin_page'))


@app.route('/admin')
@login_required
@admin_required
def admin_page():
    u_rows = get_user_db().execute('SELECT * FROM users').fetchall()
    preco_mensal = get_config('preco_mensal', '120')
    preco_vitalicio = get_config('preco_vitalicio', '1.400')
    users_processed = []

    for row in u_rows:
        u = dict(row)
        dias = 0
        if u.get('is_vitalicio') or u.get('is_admin'):
            dias = 9999
        elif u.get('validade_licenca'):
            try:
                val = datetime.fromisoformat(u['validade_licenca'])
                dias = (val - datetime.now()).days
            except:
                dias = 0
        u['dias_restantes'] = dias
        cats = u.get('categorias_permitidas')
        if cats:
            u['categorias_permitidas'] = cats.split(',')
        else:
            u['categorias_permitidas'] = []
        u['whatsapp_number'] = u.get('whatsapp_number')
        u['postar_no_mural'] = u.get('postar_no_mural', 0)
        u['tipo_campeonato'] = u.get('tipo_campeonato', 'CORRIDOS')
        users_processed.append(u)

    return render_template('admin.html', users=users_processed, preco_mensal=preco_mensal, preco_vitalicio=preco_vitalicio)


@app.route('/admin/update_prices', methods=['POST'])
@login_required
@admin_required
def update_prices():
    mensal = request.form.get('preco_mensal')
    vitalicio = request.form.get('preco_vitalicio')
    db = get_user_db()
    db.execute("INSERT OR REPLACE INTO config (chave, valor) VALUES ('preco_mensal', ?)", (mensal,))
    db.execute("INSERT OR REPLACE INTO config (chave, valor) VALUES ('preco_vitalicio', ?)", (vitalicio,))
    db.commit()
    flash('Valores atualizados com sucesso!', 'success')
    return redirect(url_for('admin_page'))


@app.route('/admin/edit_user_data/<int:user_id>', methods=['POST'])
@login_required
def edit_user_data(user_id):
    # TRAVA DE SEGURANÇA:
    # Só permite se (1) Você for o Denival OU (2) Você for um Admin logado
    if g.user.id != user_id and not g.user.is_admin:
        flash('Acesso negado. Você não tem permissão para editar outros usuários.', 'error')
        return redirect(url_for('index'))

    new_username = request.form.get('username', '').strip()
    new_password = request.form.get('password', '').strip()
    new_nome_campeonato = request.form.get('nome_campeonato', '').strip()
    new_whatsapp_number = request.form.get('whatsapp_number', '').strip()
    postar_mural = 1 if 'postar_no_mural' in request.form else 0
    novo_tipo = request.form.get('tipo_campeonato', 'CORRIDOS')

    db = get_user_db()
    query_parts = []
    user_data = []

    # Validação de nome de usuário
    if new_username:
        check = db.execute('SELECT 1 FROM users WHERE username=? AND id!=?', (new_username, user_id)).fetchone()
        if check:
            flash('Erro: Este nome de usuário já está sendo usado por outra pessoa.', 'error')
            return redirect(request.referrer or url_for('admin_page'))
        query_parts.append('username=?')
        user_data.append(new_username)

    # Alteração de Senha (Criptografada)
    if new_password:
        if not validar_senha_forte(new_password):
            flash('Senha muito curta! Use pelo menos 8 caracteres.', 'error')
            return redirect(request.referrer or url_for('admin_page'))
        query_parts.append('password_hash=?')
        user_data.append(generate_password_hash(new_password))

    # Atualiza os demais campos (Campeonato, WhatsApp, Mural, etc)
    query_parts.append('nome_campeonato=?')
    user_data.append(new_nome_campeonato)
    query_parts.append('whatsapp_number=?')
    user_data.append(new_whatsapp_number)
    query_parts.append('postar_no_mural=?')
    user_data.append(postar_mural)
    query_parts.append('tipo_campeonato=?')
    user_data.append(novo_tipo)

    if query_parts:
        query = "UPDATE users SET " + ", ".join(query_parts) + " WHERE id=?"
        user_data.append(user_id)
        db.execute(query, user_data)
        db.commit()
        flash('Dados atualizados com sucesso!', 'success')

    return redirect(request.referrer or url_for('admin_page'))


@app.route('/admin/update_permissions/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def update_permissions(user_id):
    cats_selecionadas = request.form.getlist('categorias')
    cats_str = ",".join(cats_selecionadas)
    try:
        get_user_db().execute('UPDATE users SET categorias_permitidas=? WHERE id=?', (cats_str, user_id))
        get_user_db().commit()
        flash('Permissões atualizadas!', 'success')
    except Exception as e:
        flash(f'Erro: {e}', 'error')
    return redirect(url_for('admin_page'))


@app.route('/admin/toggle_admin/<int:id>', methods=['GET'])
@login_required
@admin_required
def toggle_admin(id):
    db = get_user_db()
    u = db.execute('SELECT * FROM users WHERE id=?', [id]).fetchone()
    if u and u['username'].lower() != 'denival':
        db.execute('UPDATE users SET is_admin=? WHERE id=?', (0 if u['is_admin'] else 1, id))
        db.commit()
    return redirect(url_for('admin_page'))


@app.route('/admin/renovar_usuario_custom/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def renovar_usuario_custom(user_id):
    periodo = request.form.get('dias')
    db = get_user_db()
    user_row = db.execute('SELECT * FROM users WHERE id=?', [user_id]).fetchone()
    if not user_row:
        flash('Usuário não encontrado.', 'error')
        return redirect(url_for('admin_page'))
    u = dict(user_row)
    if periodo == 'vitalicio':
        db.execute('UPDATE users SET is_vitalicio=1, validade_licenca=NULL WHERE id=?', (user_id,))
        flash(f'Licença de {u["username"]} TORNADA VITALÍCIA!', 'success')
    else:
        try:
            dias = int(periodo)
            validade_str = u.get('validade_licenca')
            if validade_str and datetime.fromisoformat(validade_str) > datetime.now():
                data_nova = datetime.fromisoformat(validade_str) + timedelta(days=dias)
            else:
                data_nova = datetime.now() + timedelta(days=dias)
            db.execute('UPDATE users SET validade_licenca=?, is_vitalicio=0 WHERE id=?', (data_nova.isoformat(), user_id))
            flash(f'Licença de {u["username"]} renovada por {dias} dias.', 'success')
        except ValueError:
            flash('Período de renovação inválido.', 'danger')
        except Exception as e:
            flash(f'Erro ao renovar: {e}', 'danger')
    db.commit()
    return redirect(url_for('admin_page'))


@app.route('/admin/tornar_vitalicio/<int:user_id>')
@login_required
@admin_required
def tornar_vitalicio(user_id):
    db = get_user_db()
    db.execute('UPDATE users SET is_vitalicio=1, validade_licenca=NULL WHERE id=?', (user_id,))
    db.commit()
    flash('Licença tornada VITALÍCIA!', 'success')
    return redirect(url_for('admin_page'))


@app.route('/admin/bloquear_usuario/<int:user_id>')
@login_required
@admin_required
def bloquear_usuario(user_id):
    get_user_db().execute(
        'UPDATE users SET validade_licenca=?, is_vitalicio=0 WHERE id=?',
        ((datetime.now() - timedelta(days=1)).isoformat(), user_id)
    )
    get_user_db().commit()
    return redirect(url_for('admin_page'))


@app.route('/admin/delete_user/<int:user_id>')
@login_required
@admin_required
def admin_delete_user(user_id):
    db = get_user_db()
    if db.execute('SELECT * FROM users WHERE id=?', [user_id]).fetchone()['username'].lower() != 'denival':
        db.execute('DELETE FROM users WHERE id=?', [user_id])
        db.commit()
    return redirect(url_for('admin_page'))


@app.route('/simular_expiracao')
@login_required
def simular_expiracao():
    if g.user.is_admin:
        return redirect(url_for('index'))
    get_user_db().execute(
        'UPDATE users SET validade_licenca=?, is_vitalicio=0 WHERE id=?',
        ((datetime.now() - timedelta(days=1)).isoformat(), g.user.id)
    )
    get_user_db().commit()
    flash("Licença expirada para teste.", "warning")
    return redirect(url_for('index'))


@app.route('/admin/resgate')
@login_required
@admin_required
def admin_resgatar_dados():
    u_rows = get_user_db().execute('SELECT * FROM users').fetchall()
    users_processed = []
    for row in u_rows:
        u = dict(row)
        dias = 0
        if u.get('is_vitalicio') or u.get('is_admin'):
            dias = 9999
        elif u.get('validade_licenca'):
            try:
                val = datetime.fromisoformat(u['validade_licenca'])
                dias = (val - datetime.now()).days
            except:
                dias = 0
        u['dias_restantes'] = dias
        cats = u.get('categorias_permitidas')
        if cats:
            u['categorias_permitidas'] = cats.split(',')
        else:
            u['categorias_permitidas'] = []
        u['whatsapp_number'] = u.get('whatsapp_number')
        u['postar_no_mural'] = u.get('postar_no_mural', 0)
        users_processed.append(u)
    return render_template('admin.html', users=users_processed, mode='resgate')


@app.route('/admin/executar_resgate/<int:user_id>/<string:categoria>')
@login_required
@admin_required
def executar_resgate(user_id, categoria):
    origem = ARQUIVOS_LEGADO.get(categoria)
    destino = os.path.join(DATA_DIR, f"user_{user_id}_{categoria.lower()}.db")
    if not os.path.exists(origem):
        return redirect(url_for('admin_resgatar_dados'))
    try:
        shutil.copy(origem, destino)
    except:
        pass
    return redirect(url_for('admin_resgatar_dados'))


@app.route('/upload_db', methods=['POST'])
@login_required
def upload_db():
    if 'db_file' not in request.files:
        return redirect(url_for('index'))

    if not session.get('current_category_db'):
        return redirect(url_for('index'))

    file = request.files['db_file']
    if not file or not file.filename:
        flash('Nenhum arquivo enviado.', 'error')
        return redirect(url_for('index'))

    # Aceita apenas .db
    if not file.filename.lower().endswith('.db'):
        flash('Arquivo inválido. Envie apenas .db', 'error')
        return redirect(url_for('index'))

    # Destino fixo: sempre sobrescreve APENAS o DB da categoria atual
    dest_path = os.path.join(DATA_DIR, session.get('current_category_db'))

    # Proteção contra path traversal
    if not _is_safe_subpath(DATA_DIR, dest_path):
        flash('Caminho inválido.', 'error')
        return redirect(url_for('index'))

    # Salva primeiro em arquivo temporário dentro de DATA_DIR
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with tempfile.NamedTemporaryFile(delete=False, dir=DATA_DIR, suffix=".db") as tmp:
            tmp_path = tmp.name
            file.save(tmp_path)

        ok, msg = _validate_sqlite_db_file(tmp_path)
        if not ok:
            try:
                os.remove(tmp_path)
            except:
                pass
            flash(msg, 'error')
            return redirect(url_for('index'))

        # Substitui atomico (na prática)
        try:
            os.replace(tmp_path, dest_path)
        except Exception:
            # fallback
            shutil.move(tmp_path, dest_path)

        flash('Tabela carregada com sucesso!', 'success')
    except Exception as e:
        try:
            if 'tmp_path' in locals() and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except:
            pass
        flash(f'Erro ao carregar DB: {e}', 'error')

    return redirect(url_for('index'))
    file = request.files['db_file']
    if file and file.filename.endswith('.db'):
        if not session.get('current_category_db'):
            return redirect(url_for('index'))
        file.save(os.path.join(DATA_DIR, session.get('current_category_db')))
        flash('Tabela carregada!', 'success')
    return redirect(url_for('index'))


@app.route('/alterar_modo_campeonato', methods=['POST'])
@login_required
def alterar_modo_campeonato():
    novo_modo = request.form.get('modo')
    if novo_modo:
        novo_modo = novo_modo.strip()
        db = get_user_db()
        db.execute("UPDATE users SET tipo_campeonato=? WHERE id=?", (novo_modo, g.user.id))
        db.commit()
        g.user.tipo_campeonato = novo_modo
        session.pop('current_rodada_num', None)
        flash(f"Modo de campeonato alterado para {novo_modo}.", "success")
    else:
        flash("Erro: Nenhum modo selecionado.", "error")
    return redirect(url_for('index'))


@app.route('/imprimir_classificacao')
@login_required
def imprimir_classificacao():
    db = get_category_db()
    r = session.get('current_rodada_num', 1)

    try:
        times = get_classificacao(db, r)
    except:
        times = []

    try:
        artilheiros = get_artilharia(db, r)
    except:
        artilheiros = []

    try:
        goleiros = get_goleiros(db, r)
    except:
        goleiros = []

    return render_template(
        'imprimir_classificacao.html',
        times=times,
        artilheiros=artilheiros,
        goleiros=goleiros,
        rodada_num=r,
        data_geracao=datetime.now().strftime('%d/%m/%Y')
    )


@app.route('/imprimir_confrontos')
@login_required
def imprimir_confrontos():
    db = get_category_db()
    r = session.get('current_rodada_num', 1)
    try:
        confrontos = get_confrontos(db, r)
    except:
        confrontos = []
    return render_template('imprimir_confrontos.html', confrontos=confrontos, data_geracao=datetime.now().strftime('%d/%m/%Y'))


@app.route('/imprimir_mata_mata')
@login_required
def imprimir_mata_mata():
    db = get_category_db()
    r = session.get('current_rodada_num', 1)
    try:
        times = get_classificacao(db, r)[:8]
    except:
        times = []
    return render_template('imprimir_mata_mata.html', times=times, data_geracao=datetime.now().strftime('%d/%m/%Y'))


if __name__ == '__main__':
    app.run(debug=False)