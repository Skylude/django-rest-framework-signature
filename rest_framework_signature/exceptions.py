class InvalidAuthSettings(Exception):
    def __init__(self, message):
        # Call the base class constructor with the parameters it needs
        super(InvalidAuthSettings, self).__init__(message)