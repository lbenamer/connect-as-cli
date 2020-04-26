from connect_as import ConnectAs
import fire


def connect_as(
    env='preprod',
    id=None,
    org_id=None,
    role=None,
    query=None,
    ls=False
):
    conn = ConnectAs(env)

    if ls:
        return conn.display_saved_users()

    conn.connect_app()

    if id or id == 0:
        conn.search_user(id)
        conn.user_choice = 0
        conn.get_token()

    elif org_id or role or query:
        conn.select_user(org_id=org_id, role=role, query=query)
    else:
        conn.select_user()

    conn.open_browser()


if __name__ == '__main__':
    fire.Fire(connect_as)
