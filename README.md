# ProjectHUB

ProjectHUB is a comprehensive project management platform designed to facilitate team collaboration, file sharing, and task tracking. It provides a secure environment with real-time communication features for efficient project coordination and management.

## 🚀 Features

### User Authentication & Security
- **Secure Login/Registration**: Email/password authentication with JWT tokens
- **Session Persistence**: "Remember me" functionality for persistent sessions
- **Password Security**: Bcrypt hashing for password protection
- **HTTPS Support**: Secure communication with SSL/TLS

### Project Management
- **Project Dashboard**: Visual overview of all projects with status indicators
- **Project Creation**: Easy project setup with detailed configuration options
- **Progress Tracking**: Visual indicators of project completion status
- **Priority Management**: Color-coded priority levels for projects and tasks
- **Team Collaboration**: Add team members with specific roles and permissions

### Task Management
- **Kanban Board**: Drag-and-drop interface for task status updates (Todo, In Progress, Review, Done)
- **Task Assignment**: Assign tasks to specific team members
- **Due Date Tracking**: Set and monitor deadlines with overdue indicators
- **Priority Levels**: Mark tasks as high, medium, or low priority
- **Task Filtering**: Filter tasks by assignee, status, or priority
- **Search Functionality**: Quickly find tasks by name or description

### Document Management
- **File Upload/Download**: Share project-related documents with team members
- **Document Preview**: View documents directly in the browser
- **Metadata Display**: File properties like size, type, and upload date
- **Organization**: Structured document storage within projects
- **Search & Filtering**: Easily locate documents by name or type

### Real-time Communication
- **WebSocket Chat**: Instant messaging within project context
- **Chat History**: Persistent message storage and retrieval
- **End-to-End Encryption**: Secure messaging with AES-256 encryption
- **Typing Indicators**: See when team members are typing
- **Presence Awareness**: Know when team members are online

### User Interface
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Tab-based Navigation**: Easy switching between project features
- **Consistent Layout**: Standardized interface across all pages
- **Interactive Elements**: Modern UI with animations and transitions
- **Visual Indicators**: Clear status and progress visualization

## 🛠️ Technology Stack

### Backend
- **Flask**: Python web framework for API endpoints and business logic
- **SQLAlchemy**: ORM for database operations
- **SQLite**: Lightweight database for data storage
- **JWT**: JSON Web Tokens for secure authentication
- **WebSockets**: Real-time bidirectional communication for chat

### Frontend
- **HTML5/CSS3**: Modern markup and styling
- **JavaScript**: Client-side interactivity and API integration
- **Tailwind CSS**: Utility-first CSS framework for responsive design
- **Fetch API**: Asynchronous data retrieval and submission

### Security
- **Bcrypt**: Secure password hashing
- **HTTPS**: SSL/TLS for encrypted communication
- **CSRF Protection**: Cross-site request forgery prevention
- **Input Validation**: Client and server-side validation
- **End-to-End Encryption**: For chat messages using AES-256

## 📋 Project Structure

```
projecthub/
├── backend/                # Server-side code
│   ├── app.py              # Main Flask application
│   ├── chat_server.py      # WebSocket server for real-time chat
│   ├── query_db.py         # Database utility functions
│   ├── requirements.txt    # Python dependencies
│   ├── ssl/                # SSL certificates for HTTPS
│   └── static/             # Static assets for backend
├── creative-login.html     # Login page
├── projecthub-signup.html  # Registration page
├── dashboard.html          # Project listing and overview
├── view-project.html       # Detailed project view
├── tasks.html              # Task management interface
├── documents.html          # Document management interface
├── FEATURES.md             # Detailed feature documentation
├── security_notes.md       # Security implementation details
├── start_server.sh         # Server startup script
└── favicon.ico             # Site favicon
```

## 🚦 Getting Started

### Prerequisites
- Python 3.7 or higher
- Modern web browser (Chrome, Firefox, Safari, Edge)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/MukundTyagi30/projectHUB.git
   ```

2. Navigate to the project directory:
   ```bash
   cd projectHUB
   ```

3. Install required dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```

4. Start the servers using the provided script:
   ```bash
   chmod +x start_server.sh
   ./start_server.sh
   ```

5. Access the application:
   - Open your browser and navigate to `https://localhost:5000`
   - Register a new account or log in with test credentials
   - Start exploring and creating projects

## 📊 Current Development Status

ProjectHUB is currently in active development with the following features implemented:

- ✅ User authentication system
- ✅ Project dashboard and creation
- ✅ Task management with Kanban board
- ✅ Document uploading and management
- ✅ Real-time chat with WebSockets
- ✅ Project overview and team management

Upcoming features in development:
- 🔄 Enhanced reporting and analytics
- 🔄 Email notifications for important events
- 🔄 Calendar integration for deadline visualization
- 🔄 Role-based access control improvements
- 🔄 Mobile app development

## 🔒 Security Considerations

ProjectHUB implements several security features:

- **Authentication**: Secure login with JWT tokens and password hashing
- **HTTPS**: All communication encrypted with SSL/TLS
- **Data Protection**: Input validation to prevent SQL injection
- **CSRF Protection**: Tokens to prevent cross-site request forgery
- **End-to-End Encryption**: Chat messages encrypted with AES-256
- **Token Validation**: Regular validation of authentication tokens

For more details on security implementations, see `security_notes.md`.

## 🤝 Development and Contributions

This project is built as an educational platform demonstrating modern web application architecture. While currently focused on individual development, contributions may be welcomed in the future.

Areas for potential improvement:
- Enhanced mobile responsiveness
- Additional authentication methods (OAuth, SSO)
- Performance optimizations for large projects
- Expanded test coverage
- Internationalization support

## 📄 License

This project is made available for educational and personal use. All rights reserved.

## 📞 Contact

For questions about this project, please contact via GitHub. 