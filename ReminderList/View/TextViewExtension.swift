import Foundation
import UIKit

extension UITextView {
    private struct PlaceholderHolder {
        static var label = UILabel()
    }
 
    var placeholder: String? {
        get {
            return PlaceholderHolder.label.text
        }
        set {
            if let placeholderLabel = viewWithTag(-1) as? UILabel {
                placeholderLabel.text = newValue
            } else {
                let label = UILabel()
                label.text = newValue
                label.textColor = UIColor.placeholderText
                label.font = self.font
                label.tag = -1
                label.translatesAutoresizingMaskIntoConstraints = false
                self.addSubview(label)
                self.sendSubviewToBack(label)
                NSLayoutConstraint.activate([
                    label.topAnchor.constraint(equalTo: self.topAnchor, constant: 9),
                    label.leadingAnchor.constraint(equalTo: self.leadingAnchor, constant: 11)
                ])
                NotificationCenter.default.addObserver(forName: UITextView.textDidChangeNotification, object: self, queue: .main) { [weak self] _ in
                    label.isHidden = !(self?.text.isEmpty ?? true)
                }
            }
        }
    }
}
