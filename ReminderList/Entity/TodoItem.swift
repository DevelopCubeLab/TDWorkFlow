import Foundation

class TodoItem: Encodable, Decodable {
    var id: Int
    var name: String
    var checked: Bool
    
    init(id: Int, name: String, checked: Bool) {
        self.id = id
        self.name = name
        self.checked = checked
    }
}
