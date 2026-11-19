import streamlit as st

all_pages = [
    st.Page("all_pages/1_landing_page.py", title="Inicio"),
    st.Page("all_pages/2_auth_page.py", title="Registro e inicio de sesión"),
]


def main() -> None:
    pg = st.navigation(all_pages)
    pg.run()


if __name__ == "__main__":
    main()
