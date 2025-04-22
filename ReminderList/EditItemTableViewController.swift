import UIKit

protocol EditItemViewControllerInterface: AnyObject {
    func didAddText(text: String)
    func didUpdateText(text: String)
}

class EditItemViewController: UIViewController, UITextViewDelegate {

    private var hasAppeared = false

    weak var delegate: EditItemViewControllerInterface?
    private var text: String?

    let todoEditText: UITextView = {
        let textView = UITextView()
        textView.text = ""
        textView.placeholder = NSLocalizedString("InputContent", comment: "")
        textView.font = .systemFont(ofSize: 17)
        textView.backgroundColor = UIColor.systemGray6
        textView.textColor = .label
        textView.isScrollEnabled = false
        textView.translatesAutoresizingMaskIntoConstraints = false
        textView.layer.cornerRadius = 10
        textView.layer.masksToBounds = true
        textView.textContainerInset = UIEdgeInsets(top: 10, left: 10, bottom: 10, right: 8)
        textView.textContainer.lineFragmentPadding = 0
        return textView
    }()

    override func viewDidLoad() {
        super.viewDidLoad()
        title = (text == nil) ? NSLocalizedString("AddReminder", comment: "") : NSLocalizedString("EditReminder", comment: "")
        
        view.backgroundColor = .systemBackground
        let tapGesture = UITapGestureRecognizer(target: self, action: #selector(dismissKeyboard))
        view.addGestureRecognizer(tapGesture)

        let stackView = UIStackView(arrangedSubviews: [todoEditText])
        stackView.axis = .vertical
        stackView.spacing = 16
        stackView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stackView)

        NSLayoutConstraint.activate([
            stackView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 20),
            stackView.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 16),
            stackView.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -16),

            todoEditText.heightAnchor.constraint(greaterThanOrEqualToConstant: 100)
        ])

        // Done button
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "checkmark.circle.fill", withConfiguration: UIImage.SymbolConfiguration(pointSize: 20)),
            style: .plain,
            target: self,
            action: #selector(onClickDownButton)
        )
        navigationItem.rightBarButtonItem?.tintColor = .systemOrange
        // Removed: todoEditText.becomeFirstResponder()
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        if !hasAppeared {
            hasAppeared = true
            DispatchQueue.main.async {
                self.todoEditText.becomeFirstResponder()
            }
        }
    }
    
    @objc func dismissKeyboard() {
        if todoEditText.isFirstResponder {
            todoEditText.resignFirstResponder()
        } else {
            todoEditText.becomeFirstResponder()
        }
    }

    func setText(text: String?) {
        self.text = text
        todoEditText.text = text
        if let placeholderLabel = todoEditText.viewWithTag(-1) as? UILabel {
            placeholderLabel.isHidden = !(text?.isEmpty ?? true)
        }
    }

    @objc func onClickDownButton() {
        let content = todoEditText.text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !content.isEmpty else { return }

        if text == nil {
            delegate?.didAddText(text: content)
        } else {
            delegate?.didUpdateText(text: content)
        }

        navigationController?.popViewController(animated: true)
    }

    func textViewDidChange(_ textView: UITextView) {
        // No need to update table view
    }
}
