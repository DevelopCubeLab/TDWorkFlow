#if DEBUG || TESTFLIGHT
import Foundation
import UIKit

class WorkFlowViewController: UITableViewController {

    private var results: [String: WorkFlow] = [:]
    private var sortedPaths: [String] = []
    private var unexpectedPaths: [String] = []
    private var runtimePaths: [String] = []
    private var urlSchemePaths: [String] = []
    
    private let searchController = UISearchController(searchResultsController: nil)
    private var isSearching: Bool {
        return !(searchController.searchBar.text?.isEmpty ?? true)
    }
    private var filteredPaths: [String] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Scan Results"
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "Cell")
        loadScanData()
        
        searchController.searchResultsUpdater = self
        searchController.obscuresBackgroundDuringPresentation = false
        searchController.searchBar.placeholder = "Search items"
        navigationItem.searchController = searchController
        definesPresentationContext = true
    }

    private func loadScanData() {
        let defaultResults = WorkFlowController.performDefaultScan()
        let runtimeResults = WorkFlowController.performRuntimeIntegrityScan()
        let urlSchemeResults = WorkFlowController.checkSuspiciousURLSchemes()
        results = defaultResults
            .merging(runtimeResults) { _, new in new }
            .merging(urlSchemeResults) { _, new in new }
        runtimePaths = Array(runtimeResults.keys).sorted()
        urlSchemePaths = Array(urlSchemeResults.keys).sorted()
        sortedPaths = defaultResults.keys.sorted()
        unexpectedPaths = results.filter { $0.value.work.isValid != $0.value.expectation }.map { $0.key }.sorted()
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        return 5
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        switch section {
        case 0:
            return 1
        case 1:
            return isSearching ? filteredPaths.filter { unexpectedPaths.contains($0) }.count : unexpectedPaths.count
        case 2:
            return isSearching ? filteredPaths.filter { runtimePaths.contains($0) }.count : runtimePaths.count
        case 3:
            return isSearching ? filteredPaths.filter { urlSchemePaths.contains($0) }.count : urlSchemePaths.count
        case 4:
            return isSearching ? filteredPaths.count : sortedPaths.count
        default:
            return 0
        }
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        switch section {
        case 0:
            return "Info"
        case 1:
            return "Mismatched Results"
        case 2:
            return "Runtime Checks"
        case 3:
            return "URL Scheme Checks"
        case 4:
            return "All File Results"
        default:
            return nil
        }
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "Cell", for: indexPath)
        cell.selectionStyle = .none
        
        switch indexPath.section {
        case 0:
            let total = results.map { $0.value.score }.reduce(0, +)
            let average = total / Double(results.count)

            let version = UIDevice.current.systemVersion
            cell.textLabel?.numberOfLines = 0
            cell.textLabel?.text = """
            System Version: \(version)
            Mismatched Count: \(unexpectedPaths.count)
            Total Score: \(String(format: "%.2f", total))
            Average Score: \(String(format: "%.2f", average))
            The final release version will not include this page.
            """
        case 1:
            let groupPaths = unexpectedPaths
            let path = isSearching ? (filteredPaths.filter { groupPaths.contains($0) })[indexPath.row] : groupPaths[indexPath.row]
            if let result = results[path] {
                let validText = result.work.isValid ? "✅" : "❌"
                let expectedText = result.expectation ? "✅" : "❌"
                cell.textLabel?.numberOfLines = 0
                cell.textLabel?.text = """
                \(path)
                Result: \(validText) | Expected: \(expectedText) | Score: \(String(format: "%.1f", result.score))
                """
                let indicator = (result.work.isValid == result.expectation) ? "☑️" : "⚠️"
                cell.textLabel?.text? += " \(indicator)"
            }
        case 2:
            let groupPaths = runtimePaths
            let path = isSearching ? (filteredPaths.filter { groupPaths.contains($0) })[indexPath.row] : groupPaths[indexPath.row]
            if let result = results[path] {
                let validText = result.work.isValid ? "✅" : "❌"
                let expectedText = result.expectation ? "✅" : "❌"
                cell.textLabel?.numberOfLines = 0
                cell.textLabel?.text = """
                \(path)
                Result: \(validText) | Expected: \(expectedText) | Score: \(String(format: "%.1f", result.score))
                """
                let indicator = (result.work.isValid == result.expectation) ? "☑️" : "⚠️"
                cell.textLabel?.text? += " \(indicator)"
            }
        case 3:
            let groupPaths = urlSchemePaths
            let path = isSearching ? (filteredPaths.filter { groupPaths.contains($0) })[indexPath.row] : groupPaths[indexPath.row]
            if let result = results[path] {
                let validText = result.work.isValid ? "✅" : "❌"
                let expectedText = result.expectation ? "✅" : "❌"
                cell.textLabel?.numberOfLines = 0
                cell.textLabel?.text = """
                \(path)
                Detected: \(validText) | Expected: \(expectedText) | Score: \(String(format: "%.1f", result.score))
                """
                let indicator = (result.work.isValid == result.expectation) ? "☑️" : "⚠️"
                cell.textLabel?.text? += " \(indicator)"
            }
        case 4:
            let groupPaths = sortedPaths
            let path = isSearching ? (filteredPaths)[indexPath.row] : groupPaths[indexPath.row]
            if let result = results[path] {
                let validText = result.work.isValid ? "✅" : "❌"
                let expectedText = result.expectation ? "✅" : "❌"
                cell.textLabel?.numberOfLines = 0
                cell.textLabel?.text = """
                \(path)
                Exists: \(validText) | Expected: \(expectedText) | Score: \(String(format: "%.1f", result.score))
                """
                let indicator = (result.work.isValid == result.expectation) ? "☑️" : "⚠️"
                cell.textLabel?.text? += " \(indicator)"
            }
        default:
            break
        }

        return cell
    }
}

extension WorkFlowViewController: UISearchResultsUpdating {
    func updateSearchResults(for searchController: UISearchController) {
        let query = searchController.searchBar.text?.lowercased() ?? ""
        if query.isEmpty {
            filteredPaths = []
        } else {
            filteredPaths = results.keys.filter { $0.lowercased().contains(query) }.sorted()
        }
        tableView.reloadData()
    }
}
#endif
