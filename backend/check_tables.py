from app.config import settings
import psycopg2

try:
    conn = psycopg2.connect(settings.DATABASE_URL)
    cur = conn.cursor()
    cur.execute("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        ORDER BY table_name;
    """)
    tables = cur.fetchall()
    print("Tables created in Neon:")
    for table in tables:
        print(f"  - {table[0]}")
    conn.close()
except Exception as e:
    print(f"Error: {e}")