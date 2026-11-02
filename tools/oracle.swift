import Foundation
@main struct Oracle {
    static func main() async throws {
        let input = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let rows = try JSONSerialization.jsonObject(with: input) as! [[String: Any]]
        var output: [String: Bool] = [:]
        for row in rows {
            let data = try JSONSerialization.data(withJSONObject: row["proof"]!)
            let name = row["name"] as! String
            if row["kind"] as! String == "account" {
                output[name] = await LightClientProtocol.verify(try JSONDecoder().decode(LightClientProof.self, from: data))
            } else {
                output[name] = await LightClientProtocol.verify(try JSONDecoder().decode(StateDictionaryProof.self, from: data))
            }
        }
        print(String(data: try JSONEncoder().encode(output), encoding: .utf8)!)
    }
}
