import Foundation
import Vapor
import XCTest
@testable import ViadereServerKit

/// The console design system (`ConsoleDesignSystem.swift`): every component escapes text, tables sort and page from the query string without
/// script and never echo hostile parameters, the "go back" link never leaves the console, and the stylesheet stays pinned by the CSP.
final class ConsoleDesignSystemTests: XCTestCase {
    private let hostile = "<script>alert(\"x\")</script>' onmouseover='x' &"

    private func assertEscaped(_ html: String, _ label: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(html.contains("<script>"), "\(label): raw markup survived: \(html)", file: file, line: line)
        XCTAssertFalse(html.contains("' onmouseover='"), "\(label): attribute break-out survived", file: file, line: line)
        XCTAssertTrue(html.contains("&lt;script&gt;"), "\(label): text not shown escaped: \(html)", file: file, line: line)
    }

    // MARK: Escaping

    func testEveryComponentEscapesTheTextItIsGiven() {
        let h = hostile
        assertEscaped(ConsoleUI.pill(h, .danger), "pill")
        assertEscaped(ConsoleUI.button(h, .danger, name: h, value: h, ariaLabel: h, passkey: true), "button")
        assertEscaped(ConsoleUI.linkButton(h, href: "/x?\(h)", ariaLabel: h), "link button")
        assertEscaped(ConsoleUI.passkeyNote(h), "passkey note")
        assertEscaped(ConsoleUI.segmented([(h, "/a?\(h)", true)], label: h), "segmented")
        assertEscaped(ConsoleUI.form("/a?\(h)", csrf: "", ariaLabel: h, ""), "form")
        assertEscaped(ConsoleUI.hidden(h, h), "hidden")
        assertEscaped(ConsoleUI.input(h, label: h, id: h, type: h, value: h, placeholder: h, help: h, error: h, attrs: [h: h, "pattern": h]), "input")
        assertEscaped(ConsoleUI.textarea(h, label: h, value: h, placeholder: h, help: h, error: h), "textarea")
        assertEscaped(ConsoleUI.select(h, label: h, options: [ConsoleUI.Option(h, h, selected: true)], help: h, error: h), "select")
        assertEscaped(ConsoleUI.checkbox(h, value: h, label: h, help: h), "checkbox")
        assertEscaped(ConsoleUI.choices(h, legend: h, [ConsoleUI.Choice(h, h, help: h, tone: .danger)], selected: h, help: h), "choices")
        assertEscaped(ConsoleUI.fieldset(h, help: h, ""), "fieldset")
        assertEscaped(ConsoleUI.reason(id: h, label: h, help: h, placeholder: h), "reason")
        assertEscaped(ConsoleUI.card(h, id: h, description: h, ""), "card")
        assertEscaped(ConsoleUI.sectionTitle(h, description: h), "section title")
        assertEscaped(ConsoleUI.dangerZone(h, description: h, ""), "danger zone")
        assertEscaped(ConsoleUI.stat(ConsoleUI.Stat(h, h, hint: h, tone: .warning, href: "/x?\(h)")), "stat")
        assertEscaped(ConsoleUI.keyValues([(h, "")]), "key values")
        assertEscaped(ConsoleUI.callout(.danger, title: h, ""), "callout")
        assertEscaped(ConsoleUI.toast(h, tone: .danger), "toast")
        assertEscaped(ConsoleUI.empty(h, h), "empty state")
        assertEscaped(ConsoleUI.checklist([ConsoleUI.Step(false, h, "")], label: h), "checklist")
        assertEscaped(ConsoleUI.confirm(h, ariaLabel: h, ""), "confirm")
        assertEscaped(ConsoleUI.more(h, ""), "disclosure")
        assertEscaped(ConsoleUI.timeline([(titleHTML: "", meta: h, bodyHTML: "")], label: h), "timeline")
        assertEscaped(ConsoleUI.diff(before: [h, "same"], after: ["same", h + "2"], beforeTitle: h, afterTitle: h), "diff")
        assertEscaped(ConsoleUI.preview(src: "/p?\(h)", title: h, width: 10, height: 10), "preview")
        assertEscaped(ConsoleUI.table([ConsoleUI.Column(h, key: "k")], [[.text(h)]], caption: h,
                                      state: ConsoleUI.TableState(id: "t", path: "/dashboard/x", query: [URLQueryItem(name: "q", value: h)])), "table")
        assertEscaped(ConsoleUI.table([ConsoleUI.Column("A")], [], caption: h, empty: h, emptyMessage: h), "table empty state")
        assertEscaped(DashboardFormat.badge(h, "dg"), "legacy badge")
        assertEscaped(DashboardFormat.table([h], [[ConsoleUI.esc(h)]], empty: h, caption: h), "legacy table")
    }

    func testSwatchDrawsOnlyAValidatedHexColour() {
        XCTAssertTrue(ConsoleUI.swatch("#12ab34").contains("fill=\"#12ab34\""))
        let attack = ConsoleUI.swatch("#123456\" onload=\"alert(1)")
        XCTAssertFalse(attack.contains("<svg"), "anything but #RRGGBB is never put in an attribute")
        XCTAssertFalse(attack.contains("\" onload=\""))
        XCTAssertFalse(ConsoleUI.swatch("url(x)").contains("<svg"))
    }

    // MARK: Forms

    func testFieldsAreLabelledDescribedAndMarkedInvalid() {
        let html = ConsoleUI.input("email", label: "Email", type: "email", help: "We send a code.", error: "That address is not valid.", required: true)
        XCTAssertTrue(html.contains("<label for=\"f-email\">Email</label>"))
        XCTAssertTrue(html.contains("aria-describedby=\"f-email-h f-email-e\""))
        XCTAssertTrue(html.contains("aria-invalid=\"true\""))
        XCTAssertTrue(html.contains(" required"))
        XCTAssertTrue(html.contains("class=\"vmsg\">Enter an email address"), "the script-free inline hint says what is wrong")
        let optional = ConsoleUI.input("legalName", label: "Legal name", optional: true)
        XCTAssertTrue(optional.contains("(optional)"))
        XCTAssertFalse(optional.contains("aria-describedby"), "no dangling reference without help or error")
        XCTAssertEqual(ConsoleUI.fieldId("scopes[]"), "f-scopes--")
        let box = ConsoleUI.checkbox("close", label: "Close")
        XCTAssertTrue(box.hasPrefix("<label class=\"ck\"><input type=\"checkbox\""), "checkboxes are wrapped in their label")
        let reason = ConsoleUI.reason(id: "r")
        XCTAssertTrue(reason.contains("minlength=\"8\"") && reason.contains("maxlength=\"300\"") && reason.contains(" required"), "the operator reason rule, in the browser too")
    }

    func testDestructiveConfirmationNeedsNoScript() {
        let html = ConsoleUI.confirm("Remove", ariaLabel: "Remove Pat", ConsoleUI.button("Remove from the team", .dangerSolid))
        XCTAssertTrue(html.hasPrefix("<details class=\"confirm\"><summary class=\"btn d sm\" aria-label=\"Remove Pat\">Remove</summary>"))
        XCTAssertTrue(html.contains("<button class=\"btn dd\" type=\"submit\">"))
        XCTAssertFalse(html.contains("<script") || html.contains(" onclick="))
    }

    // MARK: Tables

    func testTablesSortAndPageFromTheQueryAndKeepOtherParameters() {
        let data: [(String, Int)] = [("b", 2), ("a", 10), ("c", 1)]
        let rows: [[ConsoleUI.Cell]] = data.map { [.text($0.0), .number($0.1)] }
        let columns = [ConsoleUI.Column("Name", key: "name"), ConsoleUI.Column("Count", key: "count", numeric: true)]
        let state = ConsoleUI.TableState(id: "t", path: "/dashboard/x", query: [URLQueryItem(name: "t_sort", value: "count"), URLQueryItem(name: "t_dir", value: "desc"),
                                                                               URLQueryItem(name: "m", value: "saved"), URLQueryItem(name: "days", value: "30")])
        let html = ConsoleUI.table(columns, rows, caption: "Things", state: state, pageSize: 2)
        let a = html.range(of: ">a<")!, b = html.range(of: ">b<")!
        XCTAssertLessThan(a.lowerBound, b.lowerBound, "10 before 2: numeric, descending")
        XCTAssertFalse(html.contains(">c<"), "the third row is on page 2")
        XCTAssertTrue(html.contains("aria-sort=\"descending\""))
        XCTAssertTrue(html.contains("Page 1 of 2"))
        XCTAssertTrue(html.contains("t_page=2"))
        XCTAssertTrue(html.contains("days=30"), "other parameters are kept")
        XCTAssertFalse(html.contains("m=saved"), "a one-time flash is not repeated by sort and page links")
        XCTAssertTrue(html.contains("<th scope=\"col\" class=\"num\" aria-sort=\"descending\">"))
        // Page 2, ascending by name.
        let page2 = ConsoleUI.table(columns, rows, caption: "Things", state: ConsoleUI.TableState(id: "t", path: "/dashboard/x",
            query: [URLQueryItem(name: "t_sort", value: "name"), URLQueryItem(name: "t_page", value: "2")]), pageSize: 2)
        XCTAssertTrue(page2.contains(">c<") && !page2.contains(">a<"))
        XCTAssertTrue(page2.contains("rel=\"prev\""))
    }

    func testHostileTableParametersAreIgnoredOrEscaped() {
        let rows: [[ConsoleUI.Cell]] = [[.text("one")], [.text("two")]]
        let state = ConsoleUI.TableState(id: "t", path: "//evil.example/x", query: [URLQueryItem(name: "t_sort", value: "\"><script>x</script>"),
                                                                                    URLQueryItem(name: "t_page", value: "-5"), URLQueryItem(name: "x", value: "\"><img src=x>")])
        XCTAssertEqual(state.page, 1)
        let html = ConsoleUI.table([ConsoleUI.Column("Name", key: "name")], rows, caption: "T", state: state)
        XCTAssertFalse(html.contains("<script>") || html.contains("<img"))
        XCTAssertFalse(html.contains("href=\"//"), "links stay on this site")
        XCTAssertLessThan(html.range(of: ">one<")!.lowerBound, html.range(of: ">two<")!.lowerBound, "an unknown sort key leaves the order alone")
        XCTAssertFalse(html.contains("aria-sort"))
    }

    // MARK: Navigation

    func testGoBackLinksNeverLeaveTheConsole() {
        let host = "console.viadere.com"
        XCTAssertEqual(ConsoleUI.backPath(referer: "https://console.viadere.com/dashboard/api-keys?x=1", host: host, prefix: "/dashboard"), "/dashboard/api-keys?x=1")
        XCTAssertEqual(ConsoleUI.backPath(referer: "/dashboard/compliance", host: nil, prefix: "/dashboard"), "/dashboard/compliance")
        XCTAssertNil(ConsoleUI.backPath(referer: "https://evil.example/dashboard/api-keys", host: host, prefix: "/dashboard"))
        XCTAssertNil(ConsoleUI.backPath(referer: "https://evil.example/dashboard/api-keys", host: nil, prefix: "/dashboard"))
        XCTAssertNil(ConsoleUI.backPath(referer: "//evil.example/dashboard", host: host, prefix: "/dashboard"))
        XCTAssertNil(ConsoleUI.backPath(referer: "javascript:alert(1)", host: host, prefix: "/dashboard"))
        XCTAssertNil(ConsoleUI.backPath(referer: "https://console.viadere.com/operator/policy", host: host, prefix: "/dashboard"), "the other realm is not offered")
        XCTAssertNil(ConsoleUI.backPath(referer: "https://console.viadere.com/dashboardx", host: host, prefix: "/dashboard"))
        XCTAssertNil(ConsoleUI.backPath(referer: nil, host: host, prefix: "/dashboard"))
    }

    func testBreadcrumbsFollowTheSectionsAndEveryPageHasAnIcon() {
        let trail = DashboardUI.businessCrumbs(active: "/dashboard/api-keys", title: "API keys").map(\.title)
        XCTAssertEqual(trail, ["Dashboard", "Developers", "API keys"])
        XCTAssertEqual(DashboardUI.businessCrumbs(active: "/dashboard", title: "Overview").map(\.title), ["Dashboard", "Overview"])
        XCTAssertEqual(DashboardUI.operatorCrumbs(active: "/operator/businesses", title: "Acme").map(\.title), ["Operator", "Businesses", "Acme"])
        XCTAssertEqual(DashboardUI.operatorItem(for: "/operator/applications/x")?.path, "/operator")
        XCTAssertTrue(DashboardUI.sections.contains { $0.children.contains { $0.path == ProfileConsole.path } }, "profile access is a tab of Organization")
        XCTAssertFalse(ConsoleUI.Icon.allCases.contains { $0.rawValue.lowercased().contains("shield") }, "brand: no shield imagery")
        for icon in ConsoleUI.Icon.allCases { XCTAssertTrue(ConsoleUI.icon(icon).contains("aria-hidden=\"true\""), icon.rawValue) }
    }

    // MARK: Stylesheet and CSP

    func testTheStylesheetIsSelfContainedAndPinned() {
        let css = ConsoleUI.css
        for forbidden in ["url(", "@import", "http:", "https:", "expression(", "javascript:"] { XCTAssertFalse(css.contains(forbidden), forbidden) }
        XCTAssertEqual(DashboardUI.css, css)
        for script in [false, true] {
            let csp = DashboardUI.csp(script: script, frames: true)
            XCTAssertTrue(csp.contains("style-src 'sha256-\(DashboardUI.sha256Base64(css))'"))
            XCTAssertFalse(csp.contains("unsafe-inline") || csp.contains("unsafe-eval") || csp.contains("unsafe-hashes"))
            XCTAssertTrue(csp.contains("default-src 'none'"))
        }
        XCTAssertTrue(css.contains("@media(prefers-color-scheme:dark)"))
        XCTAssertTrue(css.contains("@media(prefers-reduced-motion:reduce)"))
        XCTAssertTrue(css.contains("@media(forced-colors:active)"))
        XCTAssertTrue(css.contains(":user-invalid"), "inline validation without script")
    }
}

/// The design system on real pages: sort parameters, hostile query strings, and the error page's way back.
final class ConsoleDesignSystemPageTests: XCTestCase {
    func testSortableTablesOnRealPagesAndHostileQueriesAreEscaped() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let sorted = try await h.page("/dashboard/team?members_sort=name&members_dir=desc", owner)
            XCTAssertEqual(sorted.status, .ok)
            XCTAssertTrue(sorted.text.contains("aria-sort=\"descending\""))
            let hostile = try await h.page("/dashboard/team?members_sort=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E&x=%22%3E%3Cimg%20src%3Dx%3E", owner)
            XCTAssertEqual(hostile.status, .ok)
            XCTAssertFalse(hostile.text.contains("<script"))
            XCTAssertFalse(hostile.text.contains("<img src=x"))
            // Breadcrumbs, the grouped sidebar and the page header are on every signed-in page.
            XCTAssertTrue(sorted.text.contains("<nav class=\"crumbs\" aria-label=\"Breadcrumb\">"))
            XCTAssertTrue(sorted.text.contains("<p class=\"nav-g\" aria-hidden=\"true\">Set up</p>"))
            XCTAssertTrue(sorted.text.contains("<header class=\"ph\"><div><h1>Team</h1>"))
        }
    }

    func testAFailedFormOffersAWayBackOnlyWithinTheConsole() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let form = [("slug", "terms"), ("version", "1")]
            let back = try await h.formPost("/dashboard/compliance/accept", owner, form, headers: ["Referer": "/dashboard/compliance"])
            XCTAssertEqual(back.status, .unprocessableEntity)
            XCTAssertTrue(back.text.contains("<a class=\"btn\" href=\"/dashboard/compliance\">Go back and fix it</a>"), back.text)
            XCTAssertTrue(back.text.contains("Check: <strong>confirm</strong>"))
            let foreign = try await h.formPost("/dashboard/compliance/accept", owner, form, headers: ["Referer": "https://evil.example/dashboard/compliance"])
            XCTAssertEqual(foreign.status, .unprocessableEntity)
            XCTAssertFalse(foreign.text.contains("Go back and fix it"))
            XCTAssertFalse(foreign.text.contains("evil.example"))
        }
    }

    func testOperatorPagesUseTheStaffShell() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            let page = try await h.page("/operator", op)
            XCTAssertEqual(page.status, .ok)
            XCTAssertTrue(page.text.contains("<div class=\"shell op\">"))
            XCTAssertTrue(page.text.contains("Viadere staff"))
            XCTAssertTrue(page.text.contains("<p class=\"nav-g\" aria-hidden=\"true\">Review</p>"))
        }
    }
}
