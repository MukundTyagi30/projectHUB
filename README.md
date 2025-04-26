# ProjectHUB

ProjectHUB is a collaborative project management platform designed to facilitate team collaboration, file sharing, and task management. It offers a secure environment for teams to work together on projects efficiently.

## Features

- **Secure Authentication**: User registration and login with encrypted password storage
- **Project Management**: Create, view, and manage projects with detailed information
- **Task Tracking**: Assign and track tasks with priorities, deadlines, and status updates
- **File Sharing**: Upload, store, and download project-related documents and files
- **Real-time Chat**: Communicate with team members in real-time within projects
- **User Dashboard**: Personalized dashboard displaying relevant projects and tasks
- **HTTPS Support**: Secure communication using SSL/TLS certificates

## Technology Stack

- **Backend**: Python with Flask web framework
- **Database**: SQLite for data storage
- **Frontend**: HTML, CSS, JavaScript
- **Security**: Password hashing, HTTPS, CSRF protection
- **Real-time Communication**: WebSockets for chat functionality

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/MukundTyagi30/projectHUB.git
   ```

2. Change to the project directory:
   ```
   cd projectHUB
   ```

3. Install required packages:
   ```
   pip install -r backend/requirements.txt
   ```

4. Run the application:
   ```
   ./start_server.sh
   ```

5. Access the application at `https://localhost:8080`

## Project Structure

- `backend/`: Contains the Flask application and server logic
- `backend/static/`: Static assets for the web interface
- `backend/ssl/`: SSL certificates for HTTPS
- `*.html`: Frontend templates and pages
- `start_server.sh`: Script to start the application server

## Security Features

The application implements various security measures including:
- Password hashing
- CSRF protection
- HTTPS support
- Secure file handling
- Input validation and sanitization

## Development

This application was developed as a project management tool with a focus on security and collaboration features. See `FEATURES.md` and `security_notes.md` for additional details.

## License

This project is made available for educational and personal use.
