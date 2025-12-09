# CWAS - Community Water Access Scheduler

Production-ready Flask application for managing community water access in Madagascar.

## Features
- User authentication (Admin, Coordinator, Household roles)
- Water source management
- Booking system with time slots
- AI chatbot assistant
- Predictive maintenance
- Analytics dashboard

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```

Visit http://localhost:5000

## Demo Accounts
- Admin: admin / admin123
- Coordinator: coord_tana / coord123
- Household: razafy_family / user123

## Deploy to Render
1. Push to GitHub
2. Connect to Render
3. Deploy as Python web service

## Environment Variables
- SECRET_KEY: Session secret (auto-generated)
- ADMIN_REG_CODE: Code for admin registration
- COORD_REG_CODE: Code for coordinator registration
