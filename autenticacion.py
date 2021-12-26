# -*- coding: utf-8 -*-
"""
GIW 2021-22
Práctica 9
Grupo 9
Autores: Sergio Arroyo Galán, Víctor Fresco Perales, Hugo García González, Miguel Ángel Portocarrero Sánchez y Diego Andrés Ramón Sanchis

Sergio Arroyo Galán, Víctor Fresco Perales, Hugo García González, Miguel Ángel Portocarrero Sánchez
y Diego Andrés Ramón Sanchis declaramos que esta solución es fruto exclusivamente
de nuestro trabajo personal. No hemos sido ayudados por ninguna otra persona ni hemos
obtenido la solución de fuentes externas, y tampoco hemos compartido nuestra solución
con nadie. Declaramos además que no hemos realizado de manera deshonesta ninguna otra
actividad que pueda mejorar nuestros resultados ni perjudicar los resultados de los demás.
"""

from flask import Flask, request, session, render_template
from mongoengine import connect, Document, StringField, EmailField

import qrcode, pyotp, base64, io, onetimepass
from passlib.hash import pbkdf2_sha256

qr = qrcode.QRCode(version=1, box_size=10, border=5)

app = Flask(__name__)
connect("giw_auth")


# Clase para almacenar usuarios usando mongoengine
class User(Document):
    user_id = StringField(primary_key=True)
    full_name = StringField(min_length=2, max_length=50, required=True)
    country = StringField(min_length=2, max_length=50, required=True)
    email = EmailField(required=True)
    passwd = StringField(required=True)
    totp_secret = StringField(required=False)


################################
# ALGUNAS FUNCIONES RELEVANTES #
################################


# Función que realiza ciertas comprovaciones sobre los datos que se introducen como entrada al darse de alta
def comprobacionSignUp(d):
    if d == None:
        return 400
    elif d.get("password") != d.get("password2"):
        return ("<h1>Las contraseñas no coinciden</h1>", 400)
    elif len(User.objects(user_id=d.get("nickname"))) > 0:
        return ("<h1>El usuario ya existe</h1>", 400)
    else:
        return True

# Función para comprobar que el usuario y la contraseña son correctos
def comprobacionLogIn(d):
    # comprobar que hay datos
    if d == None:
        return 400
    # comprobar que el usuario existe en la base de datos y si la contraseña coincide
    elif len(User.objects(user_id=d.get("nickname"))) == 0 or not pbkdf2_sha256.verify(d.get("password"), User.objects.get(user_id=d.get("nickname")).passwd):
        return ("<h1>Usuario o contraseña incorrectos</h1>", 400)
    else:
        return True

# Función para comprobar que el usuario y la contraseña antigua son correctos
def comprobacionChangePassword(d):
    if d == None:
        return 400
    elif len(User.objects(user_id=d.get("nickname"))) == 0 or not pbkdf2_sha256.verify(d.get("old_password"), User.objects.get(user_id=d.get("nickname")).passwd):
        return ("<h1>Usuario o contraseña incorrecta</h1>",400)
    else: 
        return 1

# Función que recibe una contraseña en texto plano y devuelve una contraseña hash con salt y algortimo de realentizado
def hashPassword(pswd):
    return pbkdf2_sha256.using(rounds=32000, salt_size=12).hash(pswd)

# Función que dada una entrada genera una imagen png con un código qr asociado a esa entrada
def makeQrCode(inputData):
    qr.add_data(inputData)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    return img

# Función que comprueba si el TOTP es válido
def comprobarTOTP(data):
    secret = User.objects.get(user_id=data.get("nickname")).totp_secret
    return onetimepass.valid_totp(data.get('totp'), secret)

##############
# APARTADO 1 #
##############

#
# Para almacenar las claves de los usuarios, utilizamos el algoritmo de ralentizado PBKDF2 con
# SHA256 y salt que nos proporciona la librearía passlib, por lo que no guardamos las 
# contraseñas en texto plano. Además, si un atacante consiguiese acceso a la base de datos, y a la salt,
# le costaría mucho realizar un ataque de fuerza bruta sobre un usuario en concreto debido al PBKDF2
#
# A la hora de registrar un usuario nuevo, creamos el hash de la contraseña introducida con 
# pbkdf2_sha256.using(rounds=32000, salt_size=12).hash()
#
# Para comprobar si la contraseña de un usuario que se está autenticando es correcta, utilizamos
# la función pbkdf2_sha256.verify(), que acepta una contraseña en claro y un hash para determinar si
# la contraseña corresponde con dicho hash
#

@app.route("/signup", methods=["POST"])
def signup():
    # Cogemos los datos introducidos por el usuario
    data = {"nickname": request.form['nickname'], "full_name": request.form['full_name'],
            "country": request.form['country'], "email": request.form['email'], "password": request.form['password'], "password2": request.form['password2'], }

    # Realizamos un comprobación sobre los datos
    evth_ok = comprobacionSignUp(data)

    if evth_ok != True:
        return evth_ok

    # Si todo ha ido bien guardamos al usuario en la bd, la contraseña la guardamos con el correcto nivel de seguridad
    user = User(user_id=data.get("nickname"), full_name=data.get("full_name"), country=data.get("country"), email=data.get("email"), passwd=hashPassword(data.get("password")))
    user.save()
    return render_template("bienvenido.html", name=data["full_name"]), 200

@app.route("/change_password", methods=["POST"])
def change_password():
    data = {
        "nickname": request.form['nickname'],
        "old_password": request.form['old_password'],
        "new_password": request.form['new_password'],
    }
    evth_ok = comprobacionChangePassword(data)
    if evth_ok != True:
        return evth_ok
    #Si todo correcto actualizamos la bd con la passwd nueva
    User.objects.get(user_id=data.get("nickname")).passwd = data.get('new_password')
    return render_template("pass_change.html",name = User.objects.get(user_id=data.get("nickname")).full_name),200

@app.route("/login", methods=["POST"])
def login():
    # Cogemos los datos introducidos por el usuario
    data = {"nickname": request.form['nickname'],
            "password": request.form['password'], }
    # Realizamos un comprobación sobre los datos
    evth_ok = comprobacionLogIn(data)

    if evth_ok != 1:
        return evth_ok
    return render_template("bienvenido.html", name=User.objects.get(user_id=data.get("nickname")).full_name), 200


##############
# APARTADO 2 #
##############

#
# Para generar la semilla aleatoria, utilizamos la función de la librearía pyotp random_base32() 
# y la guardamos con el usuario al hacer signuo_totp. Luego, con el nickname y el secreto, generamos 
# la URL para que Google Authenticator pueda leerla, con la forma otpauth://TYPE/LABEL?PARAMETERS. 
# En nuestro caso, otpauth://totp/GIW:{nickname}?secret={secret}&issuer=GIW. Para generar el QR a partir de la URL, 
# utiliamos la librearía qrcode. Una vez tenemos el PNG, lo guardamos en un objecto de bytes, 
# lo convertimos a base64 y lo introducimos en el html para que el usuario lo pueda escanear fácilmente con el movil
#

@app.route("/signup_totp", methods=["POST"])
def signup_totp():
    # Cogemos los datos introducidos por el usuario
    #data1 = request.get_data().split('&')
    data = {"nickname": request.form['nickname'], "full_name": request.form['full_name'],
            "country": request.form['country'], "email": request.form['email'], "password": request.form['password'], "password2": request.form['password2'], }

    # Realizamos un comprobación sobre los datos
    evth_ok = comprobacionSignUp(data)

    if evth_ok != True:
        return evth_ok

    # Clave secreta aleatoria asociada al usuario  que se usará para calcular el codigo totp
    secret = pyotp.random_base32()

    # Si todo ha ido bien guardamos al usuario en la bd, la contraseña la guardamos con el correcto nivel de seguridad
    user = User(user_id=data.get("nickname"), full_name=data.get("full_name"), country=data.get(
        "country"), email=data.get("email"), passwd=hashPassword(data.get("password")), totp_secret=secret)
    user.save()

    # Generamos el segundo factor de autentificación y devolvemos la página para su configuración
    # construimos la url para que google autheticator pueda leer los datos en ella
    nickname = data.get("nickname")
    uri = f"otpauth://totp/GIW:{nickname}?secret={secret}&issuer=GIW"

    # creamos la imagen con el codigo qr
    qr_img = makeQrCode(uri)

    # queremos obtener un objeto byte-like sobre la imagen y codificarla en base 64 para poder pasarsela al template
    buff = io.BytesIO()
    qr_img.save(buff, format='PNG')
    img_byte_arr = buff.getvalue()
    image = base64.b64encode(img_byte_arr)

    return render_template('qrVerificacion.html', userId=nickname, secret=secret, image=f"data:image/png;base64, {image.decode('UTF-8')}"), 200


@app.route("/login_totp", methods=["POST"])
def login_totp():
    data = {"nickname": request.form['nickname'],
            "password": request.form['password'],
            "totp": request.form['totp']
            }
    evth_ok = comprobacionLogIn(data) and comprobarTOTP(data)
    if evth_ok != True:
        return evth_ok
    return render_template("bienvenido.html", name=User.objects.get(user_id=data.get("nickname")).full_name), 200


class FlaskConfig:
    """Configuración de Flask"""

    # Activa depurador y recarga automáticamente
    ENV = "development"
    DEBUG = True
    TEST = True
    # Imprescindible para usar sesiones
    SECRET_KEY = "la_asignatura_de_giw"
    STATIC_FOLDER = "static"
    TEMPLATES_FOLDER = "templates"


if __name__ == "__main__":
    app.config.from_object(FlaskConfig())
    app.run()
