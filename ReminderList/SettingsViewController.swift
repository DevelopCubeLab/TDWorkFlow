import Foundation
import UIKit

class SettingsViewController: UIViewController, UITableViewDelegate, UITableViewDataSource {
    
    let versionCode = "1.0"
    
    private var tableView = UITableView()
    
    private let tableCellList = [[NSLocalizedString("Version", comment: ""), "GitHub"]]
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        view.backgroundColor = .systemBackground
        title = NSLocalizedString("Settings", comment: "")
        
        // Use the new UITableView style for iOS 15 and later
        if #available(iOS 15.0, *) {
            tableView = UITableView(frame: .zero, style: .insetGrouped)
        } else {
            tableView = UITableView(frame: .zero, style: .grouped)
        }
        
        // Set the table view's delegate and data source
        tableView.delegate = self
        tableView.dataSource = self
        
        // Register table view cells
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "Cell")

        // Add the table view to the main view
        view.addSubview(tableView)

        // Set the layout for the table view
        tableView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            tableView.topAnchor.constraint(equalTo: view.topAnchor),
            tableView.leftAnchor.constraint(equalTo: view.leftAnchor),
            tableView.rightAnchor.constraint(equalTo: view.rightAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
    }
    
    // MARK: - Set the total number of sections
    func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }
    
    // MARK: - Set the number of cells in each section
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return tableCellList[section].count
    }
    
    // MARK: - Construct each cell
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        var cell = UITableViewCell(style: .default, reuseIdentifier: "Cell")
        cell.accessoryView = .none
        cell.selectionStyle = .none
        
        cell.textLabel?.text = tableCellList[indexPath.section][indexPath.row]
        cell.textLabel?.numberOfLines = 0 // Allow line breaks
        
        
        if indexPath.section == 0 { // About
            if indexPath.row == 0 {
                cell = UITableViewCell(style: .value1, reuseIdentifier: "cell")
                cell.textLabel?.text = tableCellList[indexPath.section][indexPath.row]
                let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? NSLocalizedString("Unknown", comment: "")
                if version != versionCode { // Check if the version number has been tampered with
                    cell.detailTextLabel?.text = versionCode
                } else {
                    cell.detailTextLabel?.text = version
                }
                cell.selectionStyle = .none
                cell.accessoryType = .none
            } else {
                cell.accessoryType = .disclosureIndicator
                cell.selectionStyle = .default // Enable selection effect
            }
        }
            
        return cell
    }
    
    // MARK: - Cell's click event
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        
        tableView.deselectRow(at: indexPath, animated: true)
        
#if DEBUG || TESTFLIGHT
        if indexPath.section == 0 && indexPath.row == 0 {
            let resultVC = WorkFlowViewController()
            resultVC.hidesBottomBarWhenPushed = true // Hide the bottom navigation bar
            self.navigationController?.pushViewController(resultVC, animated: true)
        }
#endif
        if indexPath.section == 0 && indexPath.row == 1 {
            if let url = URL(string: "https://github.com/DevelopCubeLab/TDWorkFlow") {
                UIApplication.shared.open(url, options: [:], completionHandler: nil)
            }
        }
        
    }
    
}
