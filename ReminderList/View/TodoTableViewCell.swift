import UIKit

class TodoTableViewCell: UITableViewCell {

    let checkBoxButton: UIButton = {
        let button = UIButton(type: .custom)
        let config = UIImage.SymbolConfiguration(pointSize: 25, weight: .regular)
        button.setImage(UIImage(systemName: "circle", withConfiguration: config), for: .normal)
        button.setImage(UIImage(systemName: "checkmark.circle.fill", withConfiguration: config), for: .selected)
        button.tintColor = .systemOrange
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }()

    let infoText: UILabel = {
        let label = UILabel()
        label.font = .systemFont(ofSize: 17)
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()

    private let hStack: UIStackView = {
        let stack = UIStackView()
        stack.axis = .horizontal
        stack.spacing = 12
        stack.alignment = .center
        stack.translatesAutoresizingMaskIntoConstraints = false
        return stack
    }()

    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)

        hStack.addArrangedSubview(checkBoxButton)
        hStack.addArrangedSubview(infoText)
        contentView.addSubview(hStack)

        NSLayoutConstraint.activate([
            checkBoxButton.widthAnchor.constraint(equalToConstant: 44),
            checkBoxButton.heightAnchor.constraint(equalToConstant: 32),
            hStack.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 8),
            hStack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -8),
            hStack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 14),
            hStack.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -8)
        ])
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func setCheckBoxSelected(select: Bool) {
        checkBoxButton.isSelected = select
    }
}
