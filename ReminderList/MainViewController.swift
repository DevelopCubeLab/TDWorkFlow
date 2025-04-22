import UIKit
import Foundation

class MainViewController: UITableViewController {

    var todoList: [TodoItem] = []
    var clickRow: Int = -1
    let storage = TodoStorageController()
    let barButtonConfiguration = UIImage.SymbolConfiguration(pointSize: 20)

    override func viewDidLoad() {
        super.viewDidLoad()
        title = NSLocalizedString("CFBundleName", comment: "")
        navigationController?.navigationBar.prefersLargeTitles = true

        todoList = storage.load()

        tableView.register(TodoTableViewCell.self, forCellReuseIdentifier: "ReminderCell")

        let addButton = UIBarButtonItem(
            image: UIImage(systemName: "plus.circle.fill", withConfiguration: barButtonConfiguration),
            style: .plain,
            target: self,
            action: #selector(addNewItem)
        )
        addButton.tintColor = .systemOrange

        let settingsButton = UIBarButtonItem(
            image: UIImage(systemName: "gearshape.fill", withConfiguration: barButtonConfiguration),
            style: .plain,
            target: self,
            action: #selector(openSettings)
        )
        settingsButton.tintColor = .systemOrange

        navigationItem.rightBarButtonItems = [addButton, settingsButton]

        navigationItem.leftBarButtonItem = editButtonItem
        editButtonItem.image = UIImage(systemName: "arrow.up.arrow.down.circle.fill", withConfiguration: barButtonConfiguration)
        editButtonItem.tintColor = .systemOrange
        
    }

    @objc func addNewItem() {
        let editVC = EditItemViewController()
        editVC.delegate = self
        navigationController?.pushViewController(editVC, animated: true)
    }

    @objc func openSettings() {
        let settingsViewController = SettingsViewController()
        settingsViewController.hidesBottomBarWhenPushed = true // Hide the bottom navigation bar
        self.navigationController?.pushViewController(settingsViewController, animated: true)
    }

    override func setEditing(_ editing: Bool, animated: Bool) {
        super.setEditing(editing, animated: animated)
        if editing {
            editButtonItem.image = UIImage(systemName: "checkmark.circle.fill", withConfiguration: barButtonConfiguration)
        } else {
            editButtonItem.image = UIImage(systemName: "arrow.up.arrow.down.circle.fill", withConfiguration: barButtonConfiguration)
        }
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return todoList.count
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "ReminderCell", for: indexPath) as! TodoTableViewCell
        cell.accessoryType = .disclosureIndicator
        let todo = todoList[indexPath.row]

        cell.setCheckBoxSelected(select: todo.checked)
        cell.infoText.textColor = todo.checked ? .tertiaryLabel : .label

        let textStyle = NSMutableAttributedString(string: todo.name)
        let textKey = todo.checked ? 1 : 0
        textStyle.addAttribute(.strikethroughStyle, value: textKey, range: NSRange(location: 0, length: textStyle.length))
        cell.infoText.attributedText = textStyle

        cell.checkBoxButton.addAction(UIAction(handler: { _ in
            todo.checked.toggle()
            self.todoList[indexPath.row] = todo
            self.storage.save(self.todoList)
            cell.setCheckBoxSelected(select: todo.checked)

            let updatedStyle = NSMutableAttributedString(string: todo.name)
            let updatedKey = todo.checked ? 1 : 0
            updatedStyle.addAttribute(.strikethroughStyle, value: updatedKey, range: NSRange(location: 0, length: updatedStyle.length))
            cell.infoText.attributedText = updatedStyle
            cell.infoText.textColor = todo.checked ? .tertiaryLabel : .label
        }), for: .touchUpInside)

        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        let editVC = EditItemViewController()
        clickRow = indexPath.row
        editVC.setText(text: todoList[clickRow].name)
        editVC.delegate = self
        navigationController?.pushViewController(editVC, animated: true)
    }

    override func tableView(_ tableView: UITableView, commit editingStyle: UITableViewCell.EditingStyle,
                            forRowAt indexPath: IndexPath) {
        if editingStyle == .delete {
            todoList.remove(at: indexPath.row)
            storage.save(todoList)
            tableView.deleteRows(at: [indexPath], with: .automatic)
        }
    }

    override func tableView(_ tableView: UITableView, moveRowAt fromIndexPath: IndexPath, to: IndexPath) {
        let moved = todoList.remove(at: fromIndexPath.row)
        todoList.insert(moved, at: to.row)
        storage.save(todoList)
    }

    override func tableView(_ tableView: UITableView, canMoveRowAt indexPath: IndexPath) -> Bool {
        true
    }
}

extension MainViewController: EditItemViewControllerInterface {
    func didAddText(text: String) {
        todoList.append(TodoItem(id: todoList.count + 1, name: text, checked: false))
        storage.save(todoList)
        tableView.insertRows(at: [IndexPath(row: todoList.count - 1, section: 0)], with: .automatic)
    }

    func didUpdateText(text: String) {
        todoList[clickRow].name = text
        storage.save(todoList)
        tableView.reloadRows(at: [IndexPath(row: clickRow, section: 0)], with: .automatic)
    }
}
