import streamlit as st
import string
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

st.set_page_config(
    page_title="Demonstração de Criptografia",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🔐 Explorando o Mundo da Criptografia")
st.markdown("""
Esta aplicação web demonstra o funcionamento de diferentes algoritmos de criptografia, desde cifras clássicas até a criptografia de chave pública moderna. Use o menu na barra lateral para navegar entre as cifras.
""")

st.sidebar.title("Menu de Cifras")
page = st.sidebar.selectbox("Escolha uma cifra para explorar",
                            ["Cifra de César", "Cifra de Vigenère", "Criptografia RSA", "Máquina Enigma"])

if page == "Cifra de César":
    st.header("📜 Cifra de César")
    st.markdown("""
    A Cifra de César é uma das mais simples e conhecidas técnicas de criptografia. É um tipo de cifra de substituição na qual cada letra do texto é substituída por outra, que se apresenta no alfabeto por um número fixo de posições à frente.
    """)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Criptografar")
        mensagem_cesar = st.text_area("Mensagem para Criptografar:", value="Estamos na aula de SCS", key="cesar_encrypt_input")
        deslocamento_cesar = st.slider("Deslocamento (Chave):", 1, 25, 9)

        def cifra_cesar(mensagem, deslocamento):
            resultado = ""
            for char in mensagem:
                if char.isupper():
                    resultado += chr((ord(char) + deslocamento - 65) % 26 + 65)
                elif char.islower():
                    resultado += chr((ord(char) + deslocamento - 97) % 26 + 97)
                else:
                    resultado += char
            return resultado

        if st.button("Criptografar Mensagem", key="cesar_encrypt"):
            if mensagem_cesar:
                mensagem_cifrada = cifra_cesar(mensagem_cesar, deslocamento_cesar)
                st.success("Mensagem Cifrada:")
                st.code(mensagem_cifrada, language='text')
            else:
                st.warning("Por favor, insira uma mensagem.")

    with col2:
        st.subheader("Descriptografar")
        mensagem_cifrada_cesar = st.text_area("Mensagem para Descriptografar:", key="cesar_decrypt_input")
        deslocamento_decrypt_cesar = st.slider("Deslocamento (Chave):", 1, 25, 9, key="cesar_decrypt_slider")

        if st.button("Descriptografar Mensagem", key="cesar_decrypt"):
            if mensagem_cifrada_cesar:
                mensagem_original = cifra_cesar(mensagem_cifrada_cesar, -deslocamento_decrypt_cesar)
                st.info("Mensagem Original:")
                st.code(mensagem_original, language='text')
            else:
                st.warning("Por favor, insira uma mensagem cifrada.")

elif page == "Cifra de Vigenère":
    st.header("🗝️ Cifra de Vigenère")
    st.markdown("""
    A Cifra de Vigenère é uma cifra de substituição polialfabética. Ela usa uma palavra-chave para determinar o deslocamento a ser aplicado a cada letra da mensagem, tornando-a mais segura que a Cifra de César.
    """)

    def vigenere_process(message, key, mode='encrypt'):
        processed_message = []
        key = key.upper()
        key_length = len(key)
        key_as_int = [ord(i) for i in key]
        message_upper = message.upper()

        for i in range(len(message_upper)):
            if message_upper[i].isalpha():
                if mode == 'encrypt':
                    value = (ord(message_upper[i]) + key_as_int[i % key_length]) % 26
                else: 
                    value = (ord(message_upper[i]) - key_as_int[i % key_length]) % 26
                processed_message.append(chr(value + 65))
            else:
                processed_message.append(message[i])
        return ''.join(processed_message)

    mensagem_vigenere = st.text_input("Digite a mensagem:", value="FUTEBOL")
    chave_vigenere = st.text_input("Digite a chave (palavra):", value="BOLA")

    if chave_vigenere and not chave_vigenere.isalpha():
        st.error("A chave deve conter apenas letras.")
    else:
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Criptografar"):
                if mensagem_vigenere and chave_vigenere:
                    encrypted = vigenere_process(mensagem_vigenere, chave_vigenere, 'encrypt')
                    st.success("Mensagem Criptografada:")
                    st.code(encrypted, language='text')
                else:
                    st.warning("Preencha a mensagem e a chave.")
        with col2:
            if st.button("Descriptografar"):
                if mensagem_vigenere and chave_vigenere:
                    decrypted = vigenere_process(mensagem_vigenere, chave_vigenere, 'decrypt')
                    st.info("Mensagem Descriptografada:")
                    st.code(decrypted, language='text')
                    st.caption("(Note que a descriptografia funcionará corretamente se a mensagem inserida for o texto cifrado).")

elif page == "Criptografia RSA":
    st.header("🔑 Criptografia RSA (Chave Pública)")
    st.markdown("""
    O RSA é um algoritmo de criptografia assimétrica, o que significa que ele utiliza um par de chaves: uma **chave pública** (que pode ser compartilhada com todos) para criptografar, e uma **chave privada** (que deve ser mantida em segredo) para descriptografar. É a base da segurança na internet moderna.
    """)

    @st.cache_resource
    def generate_keys():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_keys(private_key, public_key):
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_private, pem_public

    if 'private_key' not in st.session_state:
        st.session_state.private_key, st.session_state.public_key = generate_keys()

    private_key = st.session_state.private_key
    public_key = st.session_state.public_key

    if st.button("Gerar Novo Par de Chaves RSA"):
        st.session_state.private_key, st.session_state.public_key = generate_keys()
        st.rerun()

    pem_private, pem_public = serialize_keys(private_key, public_key)

    with st.expander("Ver Chaves Geradas"):
        st.subheader("Chave Pública")
        st.code(pem_public.decode('utf-8'), language='pem')
        st.subheader("Chave Privada")
        st.code(pem_private.decode('utf-8'), language='pem')

    st.subheader("Teste de Criptografia e Descriptografia")
    message_rsa = st.text_input("Digite a mensagem para criptografar:", value="senha 434323&¨% para transação")

    if st.button("Criptografar e Descriptografar"):
        try:
            encrypted_message = public_key.encrypt(
                message_rsa.encode('utf-8'),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            st.success("Mensagem Criptografada (em bytes):")
            st.text_area("", value=encrypted_message, height=150)

            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            st.info("Mensagem Descriptografada com Sucesso:")
            st.code(decrypted_message.decode('utf-8'), language='text')

        except Exception as e:
            st.error(f"Ocorreu um erro: {e}")

    st.subheader("Simulação de Chave Corrompida")
    st.warning("A alteração de um único byte na chave privada a tornará inútil para descriptografar. Isso demonstra a precisão e segurança do algoritmo.")
    if st.button("Tentar Descriptografar com Chave Privada Alterada"):
        encrypted_message_for_test = public_key.encrypt(
            message_rsa.encode('utf-8'),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        
        pem_private_corrupted = pem_private[:50] + b'X' + pem_private[51:]
        
        st.markdown("**Chave privada original (início):**")
        st.code(pem_private[:60].decode())
        st.markdown("**Chave privada corrompida (início):**")
        st.code(pem_private_corrupted[:60].decode())
        
        try:
            corrupted_private_key = serialization.load_pem_private_key(pem_private_corrupted, password=None, backend=default_backend())
            corrupted_private_key.decrypt(
                encrypted_message_for_test,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
        except Exception as e:
            st.error("Falha ao descriptografar! A chave corrompida não funciona.")
            st.code(str(e))

elif page == "Máquina Enigma":
    st.header("⚙️ Simulação da Máquina Enigma")
    st.markdown("""
    A Enigma foi uma máquina de criptografia famosa usada pela Alemanha na Segunda Guerra Mundial. Sua complexidade vinha de uma série de rotores que giravam a cada letra pressionada, alterando o caminho elétrico e, consequentemente, a substituição da letra. Esta é uma simulação simplificada.
    """)

    ALPHABET = string.ascii_uppercase
    ROTOR_I = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
    ROTOR_II = "AJDKSIRUXBLHWTMCQGZNPYFVOE"
    ROTOR_III = "BDFHJLCPRTXVZNYEIWGAKMUSQO"
    REFLECTOR = "YRUHQSLDPXNGOKMIEBFZCWVJAT"

    def create_plugboard(pairs_str):
        plugboard = {c: c for c in ALPHABET}
        try:
            pairs = pairs_str.upper().split()
            for pair in pairs:
                if len(pair) == 2 and pair[0] in ALPHABET and pair[1] in ALPHABET:
                    plugboard[pair[0]] = pair[1]
                    plugboard[pair[1]] = pair[0]
        except:
            st.error("Formato do plugboard inválido. Use pares de letras, ex: 'AB CD'")
        return plugboard

    def rotate(rotor):
        return rotor[1:] + rotor[0]

    def substitute(rotor, c, reverse=False):
        if reverse:
            return ALPHABET[rotor.index(c)]
        else:
            return rotor[ALPHABET.index(c)]

    def enigma_encrypt(message, plugboard_str, initial_rotors):
        plugboard = create_plugboard(plugboard_str)
        rotors = list(initial_rotors) 
        encrypted_message = []
        
        char_count = 0
        for char in message.upper():
            if char not in ALPHABET:
                encrypted_message.append(char)
                continue
            
            char_count += 1
            
            rotors[0] = rotate(rotors[0])
            if char_count % 26 == 0:
                rotors[1] = rotate(rotors[1])
            if char_count % (26*26) == 0:
                rotors[2] = rotate(rotors[2])

            char_processed = plugboard[char]
            char_processed = substitute(rotors[0], char_processed)
            char_processed = substitute(rotors[1], char_processed)
            char_processed = substitute(rotors[2], char_processed)
            char_processed = substitute(REFLECTOR, char_processed)
            char_processed = substitute(rotors[2], char_processed, reverse=True)
            char_processed = substitute(rotors[1], char_processed, reverse=True)
            char_processed = substitute(rotors[0], char_processed, reverse=True)
            char_processed = plugboard[char_processed]
            
            encrypted_message.append(char_processed)

        return ''.join(encrypted_message)

    st.subheader("Configuração da Enigma")
    plugboard_pairs = st.text_input("Configuração do Plugboard (ex: AB CD EF):", "AB CD")
    message_enigma = st.text_area("Mensagem para Criptografar:", "CUSTO MUITO ALTO")

    if st.button("Criptografar com Enigma"):
        if message_enigma:
            initial_rotors = [ROTOR_I, ROTOR_II, ROTOR_III]
            encrypted = enigma_encrypt(message_enigma, plugboard_pairs, initial_rotors)
            st.success("Mensagem Criptografada:")
            st.code(encrypted, language='text')
            st.info("Nota: Para descriptografar com a Enigma, seria necessário configurar uma máquina idêntica (mesmos rotores, mesma posição inicial e mesmo plugboard) e digitar o texto cifrado.")
        else:
            st.warning("Por favor, insira uma mensagem.")