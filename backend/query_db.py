import sqlite3
import sys

def execute_custom_query(query):
    try:
        # Connect to the database
        conn = sqlite3.connect('projecthub.db')
        cursor = conn.cursor()
        
        # Execute the custom query
        cursor.execute(query)
        
        # Check if this is a SELECT query by checking if there are results
        try:
            results = cursor.fetchall()
            
            # Get column names
            column_names = [description[0] for description in cursor.description]
            
            # Print column names
            print("\nQuery Results:")
            print(" | ".join(column_names))
            print("-" * max(80, len(" | ".join(column_names))))
            
            # Print results
            if results:
                for row in results:
                    print(" | ".join([str(val) for val in row]))
            else:
                print("No results found")
        except:
            # Not a SELECT query or no results
            conn.commit()
            print(f"\nQuery executed successfully. Rows affected: {cursor.rowcount}")
    
    except Exception as e:
        print(f"Error executing query: {e}")
    finally:
        if conn:
            conn.close()

def query_db():
    try:
        # Connect to the database
        conn = sqlite3.connect('projecthub.db')
        cursor = conn.cursor()
        
        # List all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        print("\nTables in the database:")
        print("-" * 40)
        for table in tables:
            print(table[0])
        
        # Query users table
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        
        print("\nUsers in database:")
        print("ID | Name | Email | Password (hashed) | Created At")
        print("-" * 80)
        for user in users:
            print(f"{user[0]} | {user[1]} | {user[2]} | {user[3][:10]}... | {user[4]}")
        
        # Query projects table
        cursor.execute("SELECT id, name, description, start_date, end_date, priority, progress, user_id FROM projects")
        projects = cursor.fetchall()
        
        print("\nProjects in database:")
        print("ID | Name | Description | Start Date | End Date | Priority | Progress | User ID")
        print("-" * 100)
        for p in projects:
            desc = p[2][:15] + "..." if p[2] and len(p[2]) > 15 else p[2] or "None"
            print(f"{p[0]} | {p[1]} | {desc} | {p[3]} | {p[4]} | {p[5]} | {p[6]}% | {p[7]}")
        
        # Query tasks table
        cursor.execute("SELECT * FROM tasks")
        tasks = cursor.fetchall()
        
        print("\nTasks in database:")
        print("ID | Title | Description | Priority | Due Date | Completed | Project ID | Assignee")
        print("-" * 100)
        if tasks:
            for t in tasks:
                desc = t[2][:10] + "..." if t[2] and len(t[2]) > 10 else t[2] or "None"
                print(f"{t[0]} | {t[1]} | {desc} | {t[3]} | {t[4]} | {t[5]} | {t[6]} | {t[7] or 'None'}")
        else:
            print("No tasks found")
        
        # First check project_team_members table schema
        cursor.execute("PRAGMA table_info(project_team_members)")
        columns = cursor.fetchall()
        
        print("\nProject Team Members table schema:")
        print("Column ID | Name | Type | NotNull | Default | PK")
        print("-" * 80)
        for col in columns:
            print(f"{col[0]} | {col[1]} | {col[2]} | {col[3]} | {col[4] or 'NULL'} | {col[5]}")
        
        # Now query team members with correct columns
        try:
            col_names = [col[1] for col in columns]
            col_names_str = ", ".join(col_names)
            
            cursor.execute(f"SELECT * FROM project_team_members")
            members = cursor.fetchall()
            
            print("\nTeam Members in database:")
            print(" | ".join(col_names))
            print("-" * 80)
            
            if members:
                for m in members:
                    print(" | ".join([str(val) for val in m]))
            else:
                print("No team members found")
        except sqlite3.OperationalError as e:
            print(f"Error querying team members: {e}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # If an argument is provided, treat it as a custom SQL query
        query = " ".join(sys.argv[1:])
        execute_custom_query(query)
    else:
        # Otherwise run the standard queries
        query_db() 