"""
Pre-built e-commerce notification scenarios for the demo.

Each scenario simulates a real-world notification trigger that
the notification-intelligence system would need to decide on.
"""

from typing import Dict, Any
from dataclasses import dataclass
from enum import Enum


class NotificationType(str, Enum):
    ABANDONED_CART = "abandoned_cart"
    FLASH_SALE = "flash_sale"
    BACK_IN_STOCK = "back_in_stock"
    PRICE_DROP = "price_drop"
    SHIPPING_UPDATE = "shipping_update"


@dataclass
class Scenario:
    """A pre-built notification scenario."""
    id: str
    name: str
    description: str
    notification_type: NotificationType
    notification_data: Dict[str, Any]
    context: Dict[str, Any]


# Pre-built scenarios for the demo
SCENARIOS: Dict[str, Scenario] = {
    "abandoned_cart_high": Scenario(
        id="abandoned_cart_high",
        name="Abandoned Cart - High Value",
        description="User left $189 worth of running gear in cart 45 minutes ago. Current time: 2:00 PM",
        notification_type=NotificationType.ABANDONED_CART,
        notification_data={
            "cart_value": 189.99,
            "items": ["Nike Air Zoom Pegasus", "Running Socks (3-pack)", "Water Bottle"],
            "abandoned_minutes_ago": 45,
            "cart_id": "cart_12345"
        },
        context={
            "user_browsing": False,
            "previous_purchases": 3,
            "loyalty_tier": "silver",
            "current_hour_user_timezone": 14,  # 2 PM - good time
            "notifications_sent_today": 1,
            "recent_notifications_ignored": 0,
            "user_engagement_level": "high"
        }
    ),
    "abandoned_cart_low": Scenario(
        id="abandoned_cart_low",
        name="Abandoned Cart - Low Value",
        description="User left a $12 item in cart 2 hours ago. Current time: 1:00 PM",
        notification_type=NotificationType.ABANDONED_CART,
        notification_data={
            "cart_value": 12.99,
            "items": ["Phone Case"],
            "abandoned_minutes_ago": 120,
            "cart_id": "cart_12346"
        },
        context={
            "user_browsing": False,
            "previous_purchases": 0,
            "loyalty_tier": None,
            "current_hour_user_timezone": 13
        }
    ),
    "flash_sale_electronics": Scenario(
        id="flash_sale_electronics",
        name="Flash Sale - Electronics",
        description="40% off electronics, expires in 2 hours. Current time: 3:00 PM",
        notification_type=NotificationType.FLASH_SALE,
        notification_data={
            "discount_percent": 40,
            "expires_in_hours": 2,
            "category": "Electronics",
            "featured_items": ["AirPods Pro", "iPad Mini", "Apple Watch"]
        },
        context={
            "user_interest_categories": ["Electronics", "Tech"],
            "last_purchase_category": "Electronics",
            "time_since_last_visit_hours": 48,
            "current_hour_user_timezone": 15,  # 3 PM
            "notifications_sent_today": 0,
            "recent_notifications_ignored": 0,
            "user_engagement_level": "high"
        }
    ),
    "flash_sale_fashion": Scenario(
        id="flash_sale_fashion",
        name="Flash Sale - Fashion",
        description="Summer clearance, 60% off ending tonight. Current time: 4:00 PM",
        notification_type=NotificationType.FLASH_SALE,
        notification_data={
            "discount_percent": 60,
            "expires_in_hours": 6,
            "category": "Fashion",
            "featured_items": ["Summer Dresses", "Sandals", "Sunglasses"]
        },
        context={
            "user_interest_categories": ["Fashion", "Accessories"],
            "last_purchase_category": "Fashion",
            "time_since_last_visit_hours": 24,
            "current_hour_user_timezone": 16
        }
    ),
    "back_in_stock": Scenario(
        id="back_in_stock",
        name="Back in Stock - Wishlisted Item",
        description="Previously wishlisted item is back in stock. Current time: 10:00 AM",
        notification_type=NotificationType.BACK_IN_STOCK,
        notification_data={
            "item_name": "Sony WH-1000XM5 Headphones",
            "item_price": 349.99,
            "stock_quantity": 15,
            "wishlisted_days_ago": 14
        },
        context={
            "user_checked_availability": 3,
            "similar_items_viewed": True,
            "price_alert_set": True,
            "current_hour_user_timezone": 10,  # 10 AM
            "notifications_sent_today": 0,
            "recent_notifications_ignored": 0,
            "user_engagement_level": "high"
        }
    ),
    "price_drop": Scenario(
        id="price_drop",
        name="Price Drop Alert",
        description="Item user viewed dropped 25%. Current time: 7:00 PM",
        notification_type=NotificationType.PRICE_DROP,
        notification_data={
            "item_name": "Dyson V15 Vacuum",
            "original_price": 749.99,
            "new_price": 562.49,
            "discount_percent": 25,
            "price_valid_until": "2024-12-31"
        },
        context={
            "times_viewed": 5,
            "added_to_cart_before": True,
            "comparison_shopping": True,
            "current_hour_user_timezone": 19,  # 7 PM
            "notifications_sent_today": 1,
            "recent_notifications_ignored": 0,
            "user_engagement_level": "high"
        }
    ),
    "shipping_update": Scenario(
        id="shipping_update",
        name="Shipping Update",
        description="Package arriving today. Current time: 9:00 AM",
        notification_type=NotificationType.SHIPPING_UPDATE,
        notification_data={
            "order_id": "ORD-789456",
            "status": "out_for_delivery",
            "estimated_delivery": "Today by 6 PM",
            "carrier": "UPS",
            "items_count": 2
        },
        context={
            "delivery_instructions": "Leave at door",
            "high_value_order": True,
            "signature_required": False,
            "current_hour_user_timezone": 9
        }
    ),
    # ============================================
    # NEGATIVE SCENARIOS - Should trigger skip/delay/batch
    # ============================================
    "fatigue_overload": Scenario(
        id="fatigue_overload",
        name="Notification Fatigue",
        description="User received 8 notifications today, ignored last 5. Current time: 3:00 PM",
        notification_type=NotificationType.FLASH_SALE,
        notification_data={
            "discount_percent": 20,
            "expires_in_hours": 24,
            "category": "Clothing",
            "featured_items": ["T-Shirts", "Jeans"]
        },
        context={
            "notifications_sent_today": 8,
            "recent_notifications_ignored": 5,
            "user_engagement_level": "low",
            "current_hour_user_timezone": 15,
            "user_currently_browsing": False
        }
    ),
    "midnight_promo": Scenario(
        id="midnight_promo",
        name="Late Night Promo",
        description="Flash sale notification triggered. Current time: 3:00 AM",
        notification_type=NotificationType.FLASH_SALE,
        notification_data={
            "discount_percent": 35,
            "expires_in_hours": 12,
            "category": "Electronics",
            "featured_items": ["Headphones", "Speakers"]
        },
        context={
            "current_hour_user_timezone": 3,
            "notifications_sent_today": 0,
            "user_engagement_level": "high",
            "user_currently_browsing": False
        }
    ),
    "browsing_interrupt": Scenario(
        id="browsing_interrupt",
        name="User Currently Browsing",
        description="User is actively shopping on the site. Current time: 2:00 PM",
        notification_type=NotificationType.ABANDONED_CART,
        notification_data={
            "cart_value": 89.99,
            "items": ["Wireless Mouse", "Keyboard"],
            "abandoned_minutes_ago": 15,
            "cart_id": "cart_active"
        },
        context={
            "user_currently_browsing": True,
            "user_engagement_level": "high",
            "notifications_sent_today": 1,
            "current_hour_user_timezone": 14
        }
    ),
    "low_value_spam": Scenario(
        id="low_value_spam",
        name="Low Value + Ignored User",
        description="$5 item price drop, user ignored 3 recent notifications. Current time: 2:00 PM",
        notification_type=NotificationType.PRICE_DROP,
        notification_data={
            "item_name": "Phone Charger Cable",
            "original_price": 7.99,
            "new_price": 4.99,
            "discount_percent": 37,
            "price_valid_until": "2024-12-31"
        },
        context={
            "notifications_sent_today": 4,
            "recent_notifications_ignored": 3,  # Ignored 3 recent = skip trigger
            "times_viewed": 1,
            "user_engagement_level": "medium",
            "current_hour_user_timezone": 14
        }
    ),
    "batch_candidate": Scenario(
        id="batch_candidate",
        name="Multiple Pending Notifications",
        description="Non-urgent stock alert, 3 pending notifications. Current time: 11:00 AM",
        notification_type=NotificationType.BACK_IN_STOCK,
        notification_data={
            "item_name": "Desk Organizer",
            "item_price": 24.99,
            "stock_quantity": 200,
            "wishlisted_days_ago": 30
        },
        context={
            "notifications_sent_today": 2,
            "user_engagement_level": "medium",
            "current_hour_user_timezone": 11,
            "pending_notifications": 3,
            "user_checked_availability": 1
        }
    ),
}


# Demo users at different learning stages
DEMO_USERS = {
    "new_user": {
        "id": "user_new_001",
        "name": "New User",
        "description": "Just signed up, no learned patterns",
        "pattern_count": 0,
        "analysis_mode": "full",
        "specialists_used": 5
    },
    "learning_user": {
        "id": "user_learning_002",
        "name": "Learning User",
        "description": "Some interaction history, patterns emerging",
        "pattern_count": 5,
        "analysis_mode": "moderate",
        "specialists_used": 3
    },
    "power_user": {
        "id": "user_power_003",
        "name": "Power User",
        "description": "Extensive history, confident predictions",
        "pattern_count": 15,
        "analysis_mode": "streamlined",
        "specialists_used": 2
    }
}


def get_scenario(scenario_id: str) -> Scenario | None:
    """Get a scenario by ID."""
    return SCENARIOS.get(scenario_id)


def get_all_scenarios() -> list[Scenario]:
    """Get all available scenarios."""
    return list(SCENARIOS.values())


def get_demo_user(user_id: str) -> dict | None:
    """Get a demo user by ID."""
    return DEMO_USERS.get(user_id)


def get_all_demo_users() -> list[dict]:
    """Get all demo users."""
    return list(DEMO_USERS.values())
