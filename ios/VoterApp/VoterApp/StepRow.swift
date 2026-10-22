/// One step, collapsed to a name and a state, opening to its payloads.
///
/// This is the whole of the two-audience design. Closed, it is a line a
/// policy maker reads at a glance; open, it is every byte the step
/// produced, in a form a cryptographer can copy out and check elsewhere.
/// Nothing is hidden and nothing is in the way.
///
/// The three states say themselves in words rather than in colour alone,
/// and the live step is the marked one. `CLAUDE.md` records why: marking
/// completed work and leaving the live step plain outlines everything
/// except the one box the reader has to look at.
import OVPOCKit
import SwiftUI

struct StepRow: View {
    let record: VoterFlow.Record
    @State private var open = false

    private var title: String {
        switch record.step {
        case .config: return "Pin the election configuration"
        case .keygen: return "Generate the ad-hoc key pair"
        case .blind: return "Blind the ad-hoc public key"
        case .handover: return "Hand the blinded key to the wallet"
        case .collect: return "Collect the office’s reply"
        case .cast: return "Sign the ballot"
        case .submit: return "Submit it to the ballot box"
        case .verify: return "Find it again, as cast"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { open.toggle() }
            } label: {
                HStack(alignment: .firstTextBaseline) {
                    Image(systemName: open ? "chevron.down" : "chevron.right")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(title)
                        .font(.body)
                        .multilineTextAlignment(.leading)
                    Spacer(minLength: 8)
                    Text(record.progress.rawValue)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(colour)
                }
            }
            .buttonStyle(.plain)
            .disabled(record.payload.isEmpty)

            if open {
                ForEach(record.payload, id: \.name) { field in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(field.name)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(field.value)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .padding(.vertical, 6)
        .overlay(alignment: .leading) {
            // The live step is the marked one.
            if record.progress == .awaitingYou {
                Rectangle()
                    .fill(Color.accentColor)
                    .frame(width: 3)
                    .offset(x: -12)
            }
        }
    }

    /// Colour supports the word; it never carries the meaning alone.
    private var colour: Color {
        switch record.progress {
        case .notYet: return .secondary
        case .awaitingYou: return .accentColor
        case .done: return .green
        }
    }
}
