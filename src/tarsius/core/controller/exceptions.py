class InvalidOptionValue(Exception):
    def __init__(self, opt_name, opt_value):
        super().__init__()
        self.opt_name = opt_name
        self.opt_value = opt_value

    def __str__(self):
        return f"Invalid argument for option {self.opt_name} : {self.opt_value}"
