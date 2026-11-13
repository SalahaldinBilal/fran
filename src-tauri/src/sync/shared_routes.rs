//! The category defaults as one synced item, with clouds named by identity. The settings route stays per computer.

use serde_json::{Map, Value, json};

use super::items::Item;
use super::state::{Category, SyncFile, Target};

pub const KEY: &str = "routes:categories";

pub fn is_routes(key: &str) -> bool {
    key == KEY
}

fn shared(category: Category) -> bool {
    category != Category::Settings
}

fn name(category: Category) -> Option<String> {
    serde_json::to_value(category).ok()?.as_str().map(str::to_string)
}

pub fn item(file: &SyncFile) -> Item {
    let mut content = Map::new();
    for category in Category::ALL.into_iter().filter(|category| shared(*category)) {
        let value = match file.routes.categories.get(&category) {
            Some(Target::Cloud(id)) => file.cloud(id).map(|cloud| json!({ "cloud": cloud.identity })),
            Some(Target::WithItem) => Some(json!("withItem")),
            Some(Target::Local) | None => None,
        };
        let value = value.or_else(|| file.waiting_routes.get(&category).map(|identity| json!({ "cloud": identity })));
        if let (Some(name), Some(value)) = (name(category), value) {
            content.insert(name, value);
        }
    }
    Item {
        key: KEY.to_string(),
        category: Category::Settings,
        group: None,
        owner: None,
        pinned: None,
        label: "Where things sync".to_string(),
        content: Value::Object(content),
    }
}

/// Takes the defaults from another computer. A category it doesn't name stops syncing here too.
pub fn apply(file: &mut SyncFile, content: &Value) {
    for category in Category::ALL.into_iter().filter(|category| shared(*category)) {
        file.routes.categories.remove(&category);
        file.waiting_routes.remove(&category);
        let Some(value) = name(category).and_then(|name| content.get(&name)) else {
            continue;
        };
        if value.as_str() == Some("withItem") {
            if category.is_secret() {
                file.routes.categories.insert(category, Target::WithItem);
            }
            continue;
        }
        let Some(identity) = value.get("cloud").and_then(Value::as_str) else {
            continue;
        };
        match file.cloud_by_identity(identity).map(|cloud| cloud.id.clone()) {
            Some(id) => {
                file.routes.categories.insert(category, Target::Cloud(id));
            }
            None => {
                file.waiting_routes.insert(category, identity.to_string());
            }
        }
    }
}

/// A cloud signed into here picks up the defaults that were waiting for it.
pub fn resolve_waiting(file: &mut SyncFile) {
    let waiting = std::mem::take(&mut file.waiting_routes);
    for (category, identity) in waiting {
        match file.cloud_by_identity(&identity).map(|cloud| cloud.id.clone()) {
            Some(id) => {
                file.routes.categories.insert(category, Target::Cloud(id));
            }
            None => {
                file.waiting_routes.insert(category, identity);
            }
        }
    }
}

/// Removing a cloud here keeps the defaults that point at it, so other computers keep using them.
pub fn keep_waiting(file: &mut SyncFile, cloud_id: &str) {
    let Some(identity) = file.cloud(cloud_id).map(|cloud| cloud.identity.clone()) else {
        return;
    };
    let target = Target::Cloud(cloud_id.to_string());
    for (category, _) in file.routes.categories.iter().filter(|(category, route)| **route == target && shared(**category)) {
        file.waiting_routes.insert(*category, identity.clone());
    }
}
