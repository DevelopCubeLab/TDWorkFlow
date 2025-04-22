import UIKit
import Foundation

class TodoStorageController {
    private let todoStorageKey = "StoredTodoList"

    func save(_ todos: [TodoItem]) {
        if let data = try? JSONEncoder().encode(todos) {
            UserDefaults.standard.set(data, forKey: todoStorageKey)
        }
    }

    func load() -> [TodoItem] {
        if let data = UserDefaults.standard.data(forKey: todoStorageKey),
           let todos = try? JSONDecoder().decode([TodoItem].self, from: data) {
            return todos
        }
        return []
    }
}
