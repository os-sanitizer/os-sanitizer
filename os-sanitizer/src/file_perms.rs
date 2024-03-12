use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use libc::{S_ISVTX, S_IWGRP, S_IWOTH, S_IXGRP, S_IXOTH};

pub async fn intermediaries(path: &Path) -> Vec<PathBuf> {
    assert!(
        path.is_absolute(),
        "expected path {} to be absolute",
        path.to_string_lossy()
    );
    let mut remainder = path.components();
    let mut paths = Vec::new();
    // this is guaranteed to be root dir, which cannot be symlinked
    let mut base = PathBuf::from_iter(remainder.next());
    while let Some(next) = remainder.next() {
        base.push(next);
        if let Ok(linked) = tokio::fs::read_link(&base).await {
            paths.push(base.clone());
            base.pop();
            base.extend(&linked);
        }
    }
    paths.push(base);
    paths
}

struct CheckTree<'a> {
    component: Component<'a>,
    children: Vec<CheckTree<'a>>,
}

impl<'a> CheckTree<'a> {
    fn new() -> Self {
        Self {
            component: Component::RootDir,
            children: Vec::new(),
        }
    }

    fn add(&mut self, path: &'a Path) -> bool {
        let mut modified = false;
        let mut components = path.components();
        assert_eq!(components.next(), Some(self.component));
        let mut curr = self;
        while let Some(next) = components.next() {
            match curr.children.iter().position(|e| e.component == next) {
                Some(existing) => {
                    curr = &mut curr.children[existing];
                }
                None => {
                    modified = true;
                    curr.children.push(CheckTree {
                        component: next,
                        children: Vec::new(),
                    });
                    curr = curr.children.last_mut().unwrap();
                }
            }
        }
        modified
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Who {
    OnlyRoot,
    Someone(u32),
    Everyone,
}

impl Who {
    fn apply(self, who: Who) -> Who {
        match self {
            Who::OnlyRoot => self,
            Who::Someone(existing) => match who {
                Who::Everyone => self,
                Who::Someone(other) if other == existing => self,
                _ => who,
            },
            Who::Everyone => who,
        }
    }
}

pub async fn check_ownership<P: AsRef<Path>>(
    uid_gid: u64,
    scope: P,
    intermediaries: &Vec<PathBuf>,
) -> HashMap<PathBuf, (Who, Who)> {
    let scope = scope.as_ref();
    let mut violations = HashMap::new();
    let mut check_tree = CheckTree::new();
    for path in intermediaries {
        check_tree.add(path);
    }

    let mut walk = Vec::new();
    walk.push(check_tree.children.iter());
    let mut path = PathBuf::from("/");
    let mut metas = Vec::new();
    while let Some(last) = walk.last_mut() {
        if let Some(next) = last.next() {
            path.push(next.component);
            let Ok(meta) = tokio::fs::symlink_metadata(&path).await else {
                // for whatever reason, we cannot get this metadata; fail fast
                path.pop();
                continue;
            };
            if meta.is_symlink() || meta.file_type().is_char_device() {
                path.pop();
                continue;
            }
            walk.push(next.children.iter());
            metas.push(meta);
            if !scope.starts_with(&path) {
                // skip checks for paths outside of this scope
                let mut accessible_user = Who::Everyone;
                let mut accessible_group = Who::Everyone;
                let (last, metas) = metas.split_last().unwrap();
                for meta in metas {
                    let owner = meta.uid();
                    let group = meta.gid();
                    let mode = meta.permissions().mode();
                    if mode & S_IXOTH == 0 {
                        accessible_user = if owner != 0 {
                            accessible_user.apply(Who::Someone(owner))
                        } else {
                            accessible_user.apply(Who::OnlyRoot)
                        };
                        accessible_group = if mode & S_IXGRP != 0 && group != 0 {
                            accessible_group.apply(Who::Someone(group))
                        } else {
                            accessible_group.apply(Who::OnlyRoot)
                        };
                    } else {
                        accessible_user = accessible_user.apply(Who::Everyone);
                        accessible_group = accessible_group.apply(Who::Everyone);
                    }
                }
                let mode = last.permissions().mode();
                let (mut writable_user, mut writable_group) =
                    if mode & S_IWOTH != 0 && (!last.is_dir() || mode & S_ISVTX == 0) {
                        (Who::Everyone, Who::Everyone)
                    } else {
                        (
                            if last.uid() != 0 {
                                Who::Someone(last.uid())
                            } else {
                                Who::OnlyRoot
                            },
                            if mode & S_IWGRP != 0 && last.gid() != 0 {
                                Who::Someone(last.gid())
                            } else {
                                Who::OnlyRoot
                            },
                        )
                    };

                writable_user = accessible_user.apply(writable_user);
                writable_group = accessible_group.apply(writable_group);

                let report = match writable_user {
                    Who::OnlyRoot => false,
                    Who::Someone(u) if u == uid_gid as u32 => false,
                    Who::Someone(_) | Who::Everyone => true,
                } || match writable_group {
                    Who::OnlyRoot => false,
                    Who::Someone(g) if g == (uid_gid >> 32) as u32 => false,
                    Who::Someone(_) | Who::Everyone => true,
                };

                if report {
                    violations.insert(path.to_path_buf(), (writable_user, writable_group));
                }
            }
        } else {
            walk.pop();
            path.pop();
        }
    }

    violations
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    #[test]
    fn path_witchcraft() {
        let path = PathBuf::from("/a/b/c/d");
        let up_to_a = PathBuf::from_iter(path.components().take(2));
    }
}
