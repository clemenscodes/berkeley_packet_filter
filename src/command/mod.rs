#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Command {
    MapCreation,
    MapUpdate,
    MapDeletion,
    ProgramLoad,
    ObjectPin,
    ObjectLookup,
    ProgramAttachment,
    ProgramDetachment,
}

impl From<Command> for u32 {
    fn from(command: Command) -> Self {
        match command {
            Command::MapCreation => 0,
            Command::MapUpdate => 2,
            Command::MapDeletion => 3,
            Command::ProgramLoad => 5,
            Command::ObjectPin => 6,
            Command::ObjectLookup => 7,
            Command::ProgramAttachment => 8,
            Command::ProgramDetachment => 9,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_carries_the_number_the_kernel_reads() {
        let commands = [
            Command::MapCreation,
            Command::MapUpdate,
            Command::MapDeletion,
            Command::ProgramLoad,
            Command::ObjectPin,
            Command::ObjectLookup,
            Command::ProgramAttachment,
            Command::ProgramDetachment,
        ];

        let numbers = commands.map(u32::from);

        assert_eq!(numbers, [0, 2, 3, 5, 6, 7, 8, 9]);
    }
}
