import streamlit as st

st.title("Registro y autenticación con 2FA")
st.write(
    "Aplicación del taller de seguridad: registro de usuarios con datos sensibles "
    "cifrados, segundo factor de autenticación (OTP) y descarga de usuarios en CSV."
)

st.subheader("Qué puedes hacer")
st.markdown(
    """
- **Registrarte:** la contraseña se guarda con hash y los datos sensibles, cifrados.
- **Activar el 2FA:** escanea un QR con una app de autenticación.
- **Iniciar sesión:** con usuario, contraseña y código OTP.
- **Descargar usuarios:** en CSV, con la sesión iniciada.
"""
)

st.page_link("all_pages/2_auth_page.py", label="Ir a registro e inicio de sesión")
