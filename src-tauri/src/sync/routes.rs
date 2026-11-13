use std::collections::BTreeMap;

use super::items::Item;
use super::state::{SyncFile, Target};

const MAX_OWNER_DEPTH: usize = 4;

/// Where each item syncs to: its own choice, then its group's, then its category's. None means it stays on this computer.
pub struct Homes<'a> {
    file: &'a SyncFile,
    items: &'a BTreeMap<String, Item>,
}

impl<'a> Homes<'a> {
    pub fn new(file: &'a SyncFile, items: &'a BTreeMap<String, Item>) -> Self {
        Self { file, items }
    }

    pub fn of(&self, item: &Item) -> Option<&'a str> {
        self.resolve(item, 0)
    }

    pub fn of_key(&self, key: &str) -> Option<&'a str> {
        self.items.get(key).and_then(|item| self.of(item))
    }

    fn resolve(&self, item: &Item, depth: usize) -> Option<&'a str> {
        if let Some(identity) = &item.pinned {
            return self.file.cloud_by_identity(identity).map(|cloud| cloud.id.as_str());
        }
        let routes = &self.file.routes;
        let chosen = routes
            .items
            .get(&item.key)
            .or_else(|| item.group.as_ref().and_then(|group| routes.groups.get(group)))
            .or_else(|| routes.categories.get(&item.category))?;
        match chosen {
            Target::Local => None,
            Target::Cloud(id) => self.file.cloud(id).map(|cloud| cloud.id.as_str()),
            Target::WithItem if depth < MAX_OWNER_DEPTH => {
                let owner = self.items.get(item.owner.as_deref()?)?;
                self.resolve(owner, depth + 1)
            }
            Target::WithItem => None,
        }
    }
}

/// Whether the user said this one item stays here, whatever its group and category say.
pub fn kept_local(file: &SyncFile, key: &str) -> bool {
    file.routes.items.get(key) == Some(&Target::Local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::providers::CloudKind;
    use crate::sync::state::{Category, Cloud};

    fn cloud(id: &str) -> Cloud {
        Cloud {
            id: id.to_string(),
            kind: CloudKind::FranServer,
            name: id.to_string(),
            identity: format!("identity-{id}"),
            config: serde_json::Value::Null,
            cursor: 0,
            records: BTreeMap::new(),
            dirty_since: BTreeMap::new(),
            refs: BTreeMap::new(),
            last_sync: None,
        }
    }

    fn item(key: &str, category: Category, group: Option<&str>, owner: Option<&str>) -> Item {
        Item {
            key: key.to_string(),
            category,
            group: group.map(str::to_string),
            owner: owner.map(str::to_string),
            pinned: None,
            label: key.to_string(),
            content: serde_json::Value::Null,
        }
    }

    fn items() -> BTreeMap<String, Item> {
        [
            item("connection:prod", Category::Connections, Some("connection:Work"), None),
            item("connection:blog", Category::Connections, None, None),
            item("vault:connection:prod:password", Category::Passwords, None, Some("connection:prod")),
            item("vault:connection:blog:password", Category::Passwords, None, Some("connection:blog")),
        ]
        .into_iter()
        .map(|item| (item.key.clone(), item))
        .collect()
    }

    fn file() -> SyncFile {
        SyncFile { clouds: vec![cloud("home"), cloud("work")], ..SyncFile::default() }
    }

    #[test]
    fn nothing_syncs_until_something_says_so() {
        let (file, items) = (file(), items());
        let homes = Homes::new(&file, &items);
        assert!(items.values().all(|item| homes.of(item).is_none()));
    }

    #[test]
    fn the_item_beats_its_group_and_the_group_beats_the_category() {
        let (mut file, items) = (file(), items());
        file.routes.categories.insert(Category::Connections, Target::Cloud("home".into()));
        assert_eq!(Homes::new(&file, &items).of_key("connection:prod"), Some("home"));
        assert_eq!(Homes::new(&file, &items).of_key("connection:blog"), Some("home"));

        file.routes.groups.insert("connection:Work".into(), Target::Cloud("work".into()));
        assert_eq!(Homes::new(&file, &items).of_key("connection:prod"), Some("work"));
        assert_eq!(Homes::new(&file, &items).of_key("connection:blog"), Some("home"));

        file.routes.items.insert("connection:prod".into(), Target::Cloud("home".into()));
        assert_eq!(Homes::new(&file, &items).of_key("connection:prod"), Some("home"));
    }

    #[test]
    fn keep_on_this_computer_wins_over_the_group_and_the_category() {
        let (mut file, items) = (file(), items());
        file.routes.categories.insert(Category::Connections, Target::Cloud("home".into()));
        file.routes.groups.insert("connection:Work".into(), Target::Cloud("work".into()));
        file.routes.items.insert("connection:prod".into(), Target::Local);
        assert_eq!(Homes::new(&file, &items).of_key("connection:prod"), None);
        assert!(kept_local(&file, "connection:prod"));
        assert!(!kept_local(&file, "connection:blog"));
    }

    #[test]
    fn a_password_can_follow_its_item_go_elsewhere_or_stay() {
        let (mut file, items) = (file(), items());
        file.routes.categories.insert(Category::Connections, Target::Cloud("home".into()));
        file.routes.groups.insert("connection:Work".into(), Target::Cloud("work".into()));
        assert_eq!(Homes::new(&file, &items).of_key("vault:connection:prod:password"), None);

        file.routes.categories.insert(Category::Passwords, Target::WithItem);
        assert_eq!(Homes::new(&file, &items).of_key("vault:connection:prod:password"), Some("work"));
        assert_eq!(Homes::new(&file, &items).of_key("vault:connection:blog:password"), Some("home"));

        file.routes.items.insert("vault:connection:prod:password".into(), Target::Cloud("home".into()));
        assert_eq!(Homes::new(&file, &items).of_key("vault:connection:prod:password"), Some("home"));

        file.routes.items.insert("connection:blog".into(), Target::Local);
        assert_eq!(Homes::new(&file, &items).of_key("vault:connection:blog:password"), None);
    }

    #[test]
    fn a_linked_secret_only_ever_lives_in_the_cloud_it_is_linked_to() {
        let (mut file, mut items) = (file(), items());
        let mut value = item("vault:secret:s1:value", Category::Passwords, None, Some("secret:s1"));
        value.pinned = Some("identity-work".into());
        items.insert(value.key.clone(), value);
        file.routes.categories.insert(Category::Passwords, Target::Cloud("home".into()));
        file.routes.items.insert("vault:secret:s1:value".into(), Target::Cloud("home".into()));
        assert_eq!(Homes::new(&file, &items).of_key("vault:secret:s1:value"), Some("work"));

        // On a computer that isn't signed into that cloud the value stays put instead of going to another one.
        file.clouds.retain(|cloud| cloud.id != "work");
        assert_eq!(Homes::new(&file, &items).of_key("vault:secret:s1:value"), None);
    }

    #[test]
    fn a_route_to_a_cloud_that_was_removed_means_not_synced() {
        let (mut file, items) = (file(), items());
        file.routes.categories.insert(Category::Connections, Target::Cloud("gone".into()));
        assert_eq!(Homes::new(&file, &items).of_key("connection:blog"), None);
    }
}
