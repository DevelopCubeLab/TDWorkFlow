import UIKit
import Foundation

class TodoStorageController {
    
    static let todoStorageKey = "StoredTodoList"

    func save(_ todos: [TodoItem]) {
        if let data = try? JSONEncoder().encode(todos) {
            UserDefaults.standard.set(data, forKey: TodoStorageController.todoStorageKey)
        }
    }

    func load() -> [TodoItem] {
        if let data = UserDefaults.standard.data(forKey: TodoStorageController.todoStorageKey),
           let todos = try? JSONDecoder().decode([TodoItem].self, from: data) {
            return todos
        }
        return []
    }
}
