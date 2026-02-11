"""
Django management command to create sample users
Save this as: backend/profiles/management/commands/create_sample_users.py

Run with: python manage.py create_sample_users
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from profiles.models import UserProfile
from datetime import date

User = get_user_model()


class Command(BaseCommand):
    help = 'Creates sample users with complete profiles for testing'

    def handle(self, *args, **kwargs):
        # Sample users data
        users_data = [
            {
                'username': 'sarah.johnson@example.com',
                'password': 'password123',
                'profile': {
                    'first_name': 'Sarah',
                    'date_of_birth': date(1996, 3, 15),
                    'gender': 'Woman',
                    'show_gender': True,
                    'interested_in': ['Men'],
                    'orientation': ['Straight'],
                    'show_orientation': True,
                    'relationship_type': 'Long-term relationship',
                    'distance': 50,
                    'drinking': 'Socially',
                    'smoking': 'Never',
                    'workout': 'Often',
                    'pets': 'Love pets',
                    'communication_style': ['Direct & honest', 'Regular check-ins'],
                    'response_pace': 'Within a few hours',
                    'interests': ['Hiking', 'Photography', 'Coffee shops', 'Travel', 'Yoga'],
                    'location': 'San Francisco, CA',
                    'bio': 'Adventure seeker and coffee enthusiast. Love exploring new hiking trails and capturing moments through my lens. Looking for someone to share spontaneous road trips and cozy Sunday mornings with.',
                    'conversation_starter': "What's your favorite hidden gem in the city?",
                    'social_accounts': {
                        'instagram': 'sarah.adventures',
                        'snapchat': 'sarahj_snap',
                        'whatsapp': '',
                        'twitter': '',
                        'linkedin': ''
                    }
                }
            },
            {
                'username': 'emily.chen@example.com',
                'password': 'password123',
                'profile': {
                    'first_name': 'Emily',
                    'date_of_birth': date(1998, 7, 22),
                    'gender': 'Woman',
                    'show_gender': True,
                    'interested_in': ['Men', 'Women'],
                    'orientation': ['Bisexual'],
                    'show_orientation': True,
                    'relationship_type': 'Something casual',
                    'distance': 30,
                    'drinking': 'Regularly',
                    'smoking': 'Sometimes',
                    'workout': 'Sometimes',
                    'pets': 'Own pets',
                    'communication_style': ['Playful banter', 'Quality time'],
                    'response_pace': 'Within the day',
                    'interests': ['Art', 'Music festivals', 'Gaming', 'Cooking', 'Dogs'],
                    'location': 'San Francisco, CA',
                    'bio': "Artist by day, gamer by night. My golden retriever Max is my best friend. Love indie music and trying new recipes. Let's grab boba and see where it goes!",
                    'conversation_starter': "Cats or dogs? (There's only one right answer 🐕)",
                    'social_accounts': {
                        'instagram': 'emilychen.art',
                        'whatsapp': '+14155551234',
                        'snapchat': '',
                        'twitter': '',
                        'linkedin': ''
                    }
                }
            },
            {
                'username': 'michael.rodriguez@example.com',
                'password': 'password123',
                'profile': {
                    'first_name': 'Michael',
                    'date_of_birth': date(1994, 11, 8),
                    'gender': 'Man',
                    'show_gender': True,
                    'interested_in': ['Women'],
                    'orientation': ['Straight'],
                    'show_orientation': True,
                    'relationship_type': 'Long-term relationship',
                    'distance': 40,
                    'drinking': 'Socially',
                    'smoking': 'Never',
                    'workout': 'Daily',
                    'pets': 'Love pets',
                    'communication_style': ['Deep conversations', 'Direct & honest'],
                    'response_pace': 'Within a few hours',
                    'interests': ['Fitness', 'Reading', 'Beach', 'Movies', 'Food'],
                    'location': 'San Francisco, CA',
                    'bio': "Software engineer who loves staying active. Early morning gym sessions and evening beach runs are my therapy. Bookworm who believes in meaningful connections. Let's build something real.",
                    'conversation_starter': 'What book changed your life?',
                    'social_accounts': {
                        'linkedin': 'michaelrodriguez',
                        'instagram': 'mike_fitness',
                        'whatsapp': '',
                        'snapchat': '',
                        'twitter': ''
                    }
                }
            },
            {
                'username': 'james.wilson@example.com',
                'password': 'password123',
                'profile': {
                    'first_name': 'James',
                    'date_of_birth': date(1997, 5, 19),
                    'gender': 'Man',
                    'show_gender': True,
                    'interested_in': ['Women'],
                    'orientation': ['Straight'],
                    'show_orientation': True,
                    'relationship_type': 'Dating to see where it goes',
                    'distance': 35,
                    'drinking': 'Regularly',
                    'smoking': 'Never',
                    'workout': 'Often',
                    'pets': 'None',
                    'communication_style': ['Playful banter', 'Quality time'],
                    'response_pace': 'Within the day',
                    'interests': ['Music', 'Concerts', 'Sports', 'Comedy', 'Travel'],
                    'location': 'San Francisco, CA',
                    'bio': "Music lover and sports fanatic. You can find me at concerts or watching the game. Stand-up comedy enthusiast who can't resist a good laugh. Looking for someone to share adventures and inside jokes with.",
                    'conversation_starter': "What's the best concert you've ever been to?",
                    'social_accounts': {
                        'instagram': 'jameswilson_',
                        'snapchat': 'jwilson27',
                        'whatsapp': '',
                        'twitter': '',
                        'linkedin': ''
                    }
                }
            },
            {
                'username': 'olivia.martinez@example.com',
                'password': 'password123',
                'profile': {
                    'first_name': 'Olivia',
                    'date_of_birth': date(1995, 9, 12),
                    'gender': 'Woman',
                    'show_gender': True,
                    'interested_in': ['Men'],
                    'orientation': ['Straight'],
                    'show_orientation': True,
                    'relationship_type': 'Long-term relationship',
                    'distance': 45,
                    'drinking': 'Never',
                    'smoking': 'Never',
                    'workout': 'Sometimes',
                    'pets': 'Love pets',
                    'communication_style': ['Deep conversations', 'Regular check-ins'],
                    'response_pace': 'Within a few hours',
                    'interests': ['Books', 'Yoga', 'Cooking', 'Nature', 'Wine tasting'],
                    'location': 'San Francisco, CA',
                    'bio': 'Yoga instructor and aspiring chef. I believe in mindfulness, good food, and even better conversations. Love quiet hikes and loud laughs. Seeking someone emotionally mature who values genuine connection.',
                    'conversation_starter': "What's your go-to comfort food?",
                    'social_accounts': {
                        'instagram': 'olivia.namaste',
                        'whatsapp': '+14155559876',
                        'snapchat': '',
                        'twitter': '',
                        'linkedin': ''
                    }
                }
            },
        ]

        created_count = 0
        skipped_count = 0

        for user_data in users_data:
            username = user_data['username']
            
            # Check if user already exists
            if User.objects.filter(username=username).exists():
                self.stdout.write(
                    self.style.WARNING(f'User {username} already exists, skipping...')
                )
                skipped_count += 1
                continue

            # Create Django user
            user = User.objects.create_user(
                username=username,
                email=username,
                password=user_data['password']
            )

            # Create profile
            profile_data = user_data['profile']
            UserProfile.objects.create(
                user=user,
                **profile_data
            )

            self.stdout.write(
                self.style.SUCCESS(f'✅ Created user: {username}')
            )
            created_count += 1

        self.stdout.write(
            self.style.SUCCESS(
                f'\n🎉 Done! Created {created_count} users, skipped {skipped_count} existing users.'
            )
        )
        self.stdout.write(
            self.style.WARNING(
                '\n📝 Login credentials for all users:\n'
                '   Password: password123\n'
            )
        )