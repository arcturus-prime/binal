use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[derive(Debug, Serialize, Deserialize)]
struct PrefixTreeNode<T: Default> {
    #[serde(with = "BigArray")]
    children: [usize; 255],
    data: Option<T>,
}

impl<T: Default> Default for PrefixTreeNode<T> {
    fn default() -> Self {
        Self {
            children: [0; 255],
            data: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchTree<T: Default> {
    nodes: Vec<PrefixTreeNode<T>>,

    #[serde(with = "BigArray")]
    starting_nodes: [Vec<usize>; 255],
}

impl<T: Default> Default for SearchTree<T> {
    fn default() -> Self {
        Self {
            nodes: vec![PrefixTreeNode::default()],
            starting_nodes: [const { Vec::new() }; 255],
        }
    }
}

impl<T: Default> SearchTree<T> {
    pub fn insert(&mut self, key: &str, data: T) {
        let mut index = 0;

        let mut iter = key.bytes()
        loop {
            let Some(next_char) = iter.next() else {
                break;
            };
            let length = self.nodes.len();
            let next = &mut self.nodes[index].children[next_char as usize];

            // default value of 0 means no child
            if *next == 0 {
                *next = length;
                index = length;
                self.nodes.push(PrefixTreeNode::default());
            } else {
                index = *next;
            }
        }

        self.nodes[index].data = Some(data);
    }

    pub fn search(&self, key: &str) -> Vec<&T> {
        let mut index = 0;
        let mut exhausted = false;

        let mut iter = key.bytes();
        loop {
            let Some(next_char) = iter.next() else {
                break;
            };

            let next = self.nodes[index].children[next_char as usize];
            if next == 0 {
                exhausted = true;
                break;
            }

            index = next;
        }

        if exhausted {
            return Vec::new();
        }

        let mut next_nodes = VecDeque::new();
        next_nodes.push_back(index);

        let mut node_indices = Vec::new();

        while !next_nodes.is_empty() {
            let next = next_nodes.pop_front().unwrap();

            for i in 0..255 {
                if self.nodes[next].children[i] != 0 {
                    next_nodes.push_back(self.nodes[next].children[i]);
                }
            }

            if let Some(data) = &self.nodes[next].data {
                node_indices.push(data);
            }
        }

        return node_indices;
    }
}
