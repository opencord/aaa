package foo.opencord.aaa.api;

/*
 * The StateMachine is just an implementation detail.. it is not a primary
 * actor in the situation being modeled. Those would be more like:
 *
 *  + Supplicant
 *  + SupplicantSession
 *  + AaaService
 *  + RadiusService
 *  etc.
 */

/**
 * Exception for the State Machine.
 */
// TODO: Strongly recommend renaming this to AaaException
public class StateMachineException extends Exception {

    public StateMachineException(String message) {
        super(message);
    }
}
